package dev.sanyam.cg.analysis;

import static org.assertj.core.api.Assertions.assertThat;

import dev.sanyam.cg.finding.Severity;
import java.util.List;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.json.JsonMapper;

/** Each scanner's real JSON shape, parsed without running the tools. */
class ScannersParsingTests {

    Scanners scanners = new Scanners(JsonMapper.builder().build(), "p/python", true);

    @Test
    void parsesSemgrep() {
        String json = """
                {"results":[{"check_id":"python.lang.security.audit.formatted-sql-query.formatted-sql-query",
                 "path":"./app.py","start":{"line":3,"col":5},"end":{"line":4,"col":2},
                 "extra":{"message":" Detected SQL built from strings. ","severity":"ERROR","lines":"q = ..."}}],
                 "errors":[],"version":"1.185.0"}""";

        assertThat(scanners.parseSemgrep(json)).containsExactly(new RawFinding("semgrep", "formatted-sql-query",
                Severity.HIGH, "app.py", 3, 4, "Detected SQL built from strings."));
        assertThat(scanners.parseSemgrep("{\"results\":[]}")).isEmpty();
    }

    @Test
    void parsesBanditAndIgnoresAssertInTests() {
        String json = """
                {"errors":[],"results":[
                 {"filename":"./app.py","line_number":5,"line_range":[5,6],"issue_severity":"HIGH",
                  "issue_confidence":"HIGH","issue_text":"subprocess call with shell=True","test_id":"B602"},
                 {"filename":"./tests/test_app.py","line_number":2,"line_range":[2],"issue_severity":"LOW",
                  "issue_text":"Use of assert detected.","test_id":"B101"},
                 {"filename":"./app.py","line_number":9,"line_range":[9],"issue_severity":"LOW",
                  "issue_text":"Use of assert detected.","test_id":"B101"}]}""";

        List<RawFinding> found = scanners.parseBandit(json);

        assertThat(found).extracting(RawFinding::ruleId, RawFinding::file, RawFinding::startLine, RawFinding::endLine)
                .containsExactly(
                        org.assertj.core.groups.Tuple.tuple("B602", "app.py", 5, 6),
                        org.assertj.core.groups.Tuple.tuple("B101", "app.py", 9, 9));  // assert outside tests stays
    }

    @Test
    void parsesGitleaks() {
        String json = """
                [{"RuleID":"github-pat","File":"config.py","StartLine":1,"EndLine":1,
                  "Description":"GitHub Personal Access Token","Secret":"REDACTED"}]""";

        assertThat(scanners.parseGitleaks(json)).containsExactly(new RawFinding("gitleaks", "github-pat",
                Severity.HIGH, "config.py", 1, 1, "GitHub Personal Access Token"));
    }

    @Test
    void recognisesTestFiles() {
        assertThat(Scanners.isTestFile("tests/helpers.py")).isTrue();
        assertThat(Scanners.isTestFile("src/test_app.py")).isTrue();
        assertThat(Scanners.isTestFile("app_test.py")).isTrue();
        assertThat(Scanners.isTestFile("src/contest.py")).isFalse();
    }
}
