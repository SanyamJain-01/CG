package dev.sanyam.cg.analysis;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import dev.sanyam.cg.finding.Severity;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import tools.jackson.databind.ObjectMapper;

/**
 * Runs Semgrep, Bandit and Gitleaks on an extracted folder and turns their JSON into RawFindings. A scanner that is
 * missing, crashes or times out is reported in errors(); the others still run, so one broken tool can never turn
 * into a silent "no issues found".
 */
@Component
public class Scanners {

    static final Duration TIMEOUT = Duration.ofSeconds(120);

    private static final Logger log = LoggerFactory.getLogger(Scanners.class);

    private final ObjectMapper json;
    private final String semgrepConfig;
    private final boolean enabled;

    public Scanners(ObjectMapper json,
                    @Value("${cg.scanners.semgrep-config:p/python}") String semgrepConfig,
                    @Value("${cg.scanners.enabled:true}") boolean enabled) {
        this.json = json;
        // a rules file on disk is used as an absolute path (scanners run inside the scan folder);
        // anything else, like "p/python", is a Semgrep registry name and needs network access
        Path rules = Path.of(semgrepConfig);
        this.semgrepConfig = Files.isRegularFile(rules) ? rules.toAbsolutePath().toString() : semgrepConfig;
        this.enabled = enabled;
    }

    public AnalysisResult scan(Path root) {
        if (!enabled) {
            return AnalysisResult.empty();
        }
        List<RawFinding> findings = new ArrayList<>();
        List<String> errors = new ArrayList<>();
        runTool("semgrep", root, findings, errors);
        runTool("bandit", root, findings, errors);
        runTool("gitleaks", root, findings, errors);
        return new AnalysisResult(findings, errors);
    }

    private void runTool(String name, Path root, List<RawFinding> findings, List<String> errors) {
        try {
            findings.addAll(switch (name) {
                case "semgrep" -> semgrep(root);
                case "bandit" -> bandit(root);
                default -> gitleaks(root);
            });
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            errors.add(name + ": interrupted");
        } catch (Exception e) {
            String reason = e instanceof IOException && String.valueOf(e.getMessage()).contains("Cannot run program")
                    ? "not installed" : e.getClass().getSimpleName() + ": " + e.getMessage();
            errors.add((name + ": " + reason).substring(0, Math.min(200, name.length() + 2 + reason.length())));
            log.warn("scanner.failed tool={} reason={}", name, reason);
        }
    }

    // ---------- Semgrep ----------

    private List<RawFinding> semgrep(Path root) throws IOException, InterruptedException {
        ProcessRunner.Result r = ProcessRunner.run(List.of("semgrep", "scan", "--config", semgrepConfig, "--json",
                "--metrics", "off", "--disable-version-check", "--quiet", "--timeout", "30", "."), root, TIMEOUT);
        if (r.exitCode() != 0 && r.exitCode() != 1) {  // 0 = ran fine, 1 = ran and found issues
            throw new ScannerException("exit " + r.exitCode() + " " + tail(r.stderr()));
        }
        return parseSemgrep(r.stdout());
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record SemgrepOutput(List<SemgrepResult> results) {
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record SemgrepResult(@JsonProperty("check_id") String checkId, String path, Position start, Position end,
                                Extra extra) {
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Position(int line) {
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Extra(String message, String severity) {
    }

    List<RawFinding> parseSemgrep(String output) {
        SemgrepOutput parsed = json.readValue(output, SemgrepOutput.class);
        List<RawFinding> out = new ArrayList<>();
        for (SemgrepResult r : parsed.results() == null ? List.<SemgrepResult>of() : parsed.results()) {
            String rule = r.checkId().substring(r.checkId().lastIndexOf('.') + 1);  // drop the long registry prefix
            int start = Math.max(1, r.start().line());
            int end = Math.max(start, r.end() == null ? start : r.end().line());
            out.add(new RawFinding("semgrep", rule, Severity.normalize(r.extra().severity()), clean(r.path()),
                    start, end, r.extra().message().strip()));
        }
        return out;
    }

    // ---------- Bandit ----------

    private List<RawFinding> bandit(Path root) throws IOException, InterruptedException {
        ProcessRunner.Result r = ProcessRunner.run(List.of("bandit", "-r", ".", "-f", "json", "-q"), root, TIMEOUT);
        if (r.exitCode() != 0 && r.exitCode() != 1) {
            throw new ScannerException("exit " + r.exitCode() + " " + tail(r.stderr()));
        }
        return r.stdout().isBlank() ? List.of() : parseBandit(r.stdout());
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record BanditOutput(List<BanditResult> results) {
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record BanditResult(@JsonProperty("test_id") String testId, String filename,
                               @JsonProperty("line_number") int lineNumber,
                               @JsonProperty("line_range") List<Integer> lineRange,
                               @JsonProperty("issue_severity") String issueSeverity,
                               @JsonProperty("issue_text") String issueText) {
    }

    List<RawFinding> parseBandit(String output) {
        BanditOutput parsed = json.readValue(output, BanditOutput.class);
        List<RawFinding> out = new ArrayList<>();
        for (BanditResult r : parsed.results() == null ? List.<BanditResult>of() : parsed.results()) {
            String file = clean(r.filename());
            if (r.testId().equals("B101") && isTestFile(file)) {
                continue;  // assert is how tests work, not a vulnerability
            }
            int start = Math.max(1, r.lineNumber());
            int end = r.lineRange() == null || r.lineRange().isEmpty() ? start
                    : Math.max(start, r.lineRange().getLast());
            out.add(new RawFinding("bandit", r.testId(), Severity.normalize(r.issueSeverity()), file, start, end,
                    r.issueText().strip()));
        }
        return out;
    }

    // ---------- Gitleaks ----------

    private List<RawFinding> gitleaks(Path root) throws IOException, InterruptedException {
        Path report = Files.createTempFile("cg-gitleaks", ".json");  // outside the scan folder, so it isn't scanned
        try {
            ProcessRunner.Result r = ProcessRunner.run(List.of("gitleaks", "dir", ".", "--no-banner", "--redact",
                    "--report-format", "json", "--report-path", report.toString()), root, TIMEOUT);
            if (r.exitCode() != 0 && r.exitCode() != 1) {  // 1 = leaks found
                throw new ScannerException("exit " + r.exitCode() + " " + tail(r.stderr()));
            }
            String body = new String(Files.readAllBytes(report), StandardCharsets.UTF_8);
            return body.isBlank() ? List.of() : parseGitleaks(body);
        } finally {
            Files.deleteIfExists(report);
        }
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record GitleaksResult(@JsonProperty("RuleID") String ruleId, @JsonProperty("File") String file,
                                 @JsonProperty("StartLine") int startLine, @JsonProperty("EndLine") int endLine,
                                 @JsonProperty("Description") String description) {
    }

    List<RawFinding> parseGitleaks(String output) {
        List<RawFinding> out = new ArrayList<>();
        for (GitleaksResult r : json.readValue(output, GitleaksResult[].class)) {
            int start = Math.max(1, r.startLine());
            out.add(new RawFinding("gitleaks", r.ruleId(), Severity.HIGH, clean(r.file()), start,
                    Math.max(start, r.endLine()), r.description().strip()));
        }
        return out;
    }

    // ---------- helpers ----------

    /** Tools print "./app.py" or "app.py"; store one form. */
    static String clean(String path) {
        String p = path.replace('\\', '/');
        while (p.startsWith("./")) {
            p = p.substring(2);
        }
        return p;
    }

    static boolean isTestFile(String path) {
        String name = path.substring(path.lastIndexOf('/') + 1).toLowerCase(Locale.ROOT);
        return name.startsWith("test_") || name.endsWith("_test.py") || ("/" + path).contains("/tests/");
    }

    private static String tail(String text) {
        String t = text.strip();
        return t.length() > 150 ? "…" + t.substring(t.length() - 150) : t;
    }
}
