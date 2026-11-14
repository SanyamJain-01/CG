package dev.sanyam.cg.analysis;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Set;

/**
 * Attaches the code each finding points at, removes duplicates and keeps the most severe ones. The snippet is copied
 * now because the extracted files are deleted after the scan; it's what makes every finding checkable later.
 */
public final class Evidence {

    public static final int MAX_FINDINGS = 500;
    static final int CONTEXT_LINES = 2;
    static final int MAX_SNIPPET_CHARS = 2_000;
    static final String REDACTED = "[secret redacted]";

    public record Draft(RawFinding raw, String snippet, String fingerprint) {
    }

    private Evidence() {
    }

    public static List<Draft> attach(List<RawFinding> findings, Path root) {
        Path base = root.toAbsolutePath().normalize();
        List<RawFinding> sorted = new ArrayList<>(findings);
        sorted.sort(Comparator.comparing(RawFinding::severity).thenComparing(RawFinding::file)
                .thenComparingInt(RawFinding::startLine));
        Set<String> seenLines = new HashSet<>();
        Set<String> seenFingerprints = new HashSet<>();
        List<Draft> drafts = new ArrayList<>();
        for (RawFinding f : sorted) {
            // Semgrep and Bandit often flag the same line; the most severe one (first after sorting) wins
            if (!seenLines.add(f.file() + ":" + f.startLine())) {
                continue;
            }
            List<String> lines = readLines(base, f.file());
            String fingerprint = fingerprint(f, lines);
            if (!seenFingerprints.add(fingerprint)) {
                continue;
            }
            drafts.add(new Draft(f, snippet(f, lines), fingerprint));
            if (drafts.size() == MAX_FINDINGS) {  // ponytail: cap keeps one huge repo from flooding the database
                break;
            }
        }
        return drafts;
    }

    static String snippet(RawFinding f, List<String> lines) {
        if (f.tool().equals("gitleaks")) {
            return REDACTED;  // never store or display the secret itself
        }
        if (lines.isEmpty()) {
            return "";
        }
        int from = Math.max(0, f.startLine() - 1 - CONTEXT_LINES);
        int to = Math.min(lines.size(), f.endLine() + CONTEXT_LINES);
        if (from >= to) {
            return "";
        }
        String text = String.join("\n", lines.subList(from, to));
        return text.length() > MAX_SNIPPET_CHARS ? text.substring(0, MAX_SNIPPET_CHARS) + "\n…" : text;
    }

    /** Stable across scans of the same code, so later versions can show "new since last scan". */
    static String fingerprint(RawFinding f, List<String> lines) {
        // for secrets, hash the position, not the line: a hash of a short secret could be brute-forced
        String anchor = f.tool().equals("gitleaks") || f.startLine() > lines.size()
                ? "line " + f.startLine()
                : lines.get(f.startLine() - 1).strip();
        return sha256(f.tool() + "|" + f.ruleId() + "|" + f.file() + "|" + anchor);
    }

    private static List<String> readLines(Path base, String file) {
        Path path = base.resolve(file).normalize();
        if (!path.startsWith(base) || !Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) {
            return List.of();  // a scanner pointing outside the scan folder gets no snippet
        }
        try {
            return List.of(new String(Files.readAllBytes(path), StandardCharsets.UTF_8).split("\n", -1));
        } catch (IOException e) {
            return List.of();
        }
    }

    private static String sha256(String text) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(text.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
