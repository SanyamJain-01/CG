package dev.sanyam.cg.analysis;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import tools.jackson.databind.json.JsonMapper;

/** Runs the installed scanners on a known-vulnerable file. Skipped (not failed) on machines without them. */
class RealScannersTests {

    static final String VULN = """
            import sqlite3, subprocess
            def get_user(name):
                return sqlite3.connect("db").execute("SELECT * FROM users WHERE name = '%s'" % name)
            def run(cmd):
                return subprocess.call(cmd, shell=True)
            """;

    @TempDir Path dir;

    @Test
    void installedScannersFindTheKnownIssues() throws Exception {
        assumeTrue(installed("bandit"), "bandit is not installed");
        Files.writeString(dir.resolve("vuln.py"), VULN);

        AnalysisResult result = new Scanners(JsonMapper.builder().build(), "p/python", true).scan(dir);

        assertThat(result.errors()).noneMatch(e -> e.startsWith("bandit"));
        assertThat(result.findings()).anyMatch(f -> f.startLine() == 3);  // SQL injection
        assertThat(result.findings()).anyMatch(f -> f.startLine() == 5);  // shell=True
    }

    private static boolean installed(String tool) {
        try {
            Process p = new ProcessBuilder(tool, "--version").redirectErrorStream(true).start();
            return p.waitFor(30, TimeUnit.SECONDS) && p.exitValue() == 0;
        } catch (Exception e) {
            return false;
        }
    }
}
