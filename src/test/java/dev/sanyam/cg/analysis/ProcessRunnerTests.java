package dev.sanyam.cg.analysis;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Plain unit tests: no Spring, no database. */
class ProcessRunnerTests {

    @TempDir Path dir;

    @Test
    void timeoutAlsoKillsChildProcesses() throws Exception {
        // like Semgrep, the process starts a long-running child of its own
        assertThatThrownBy(() -> ProcessRunner.run(List.of("sh", "-c", "sleep 300 & echo $! > child.pid; wait"),
                dir, Duration.ofSeconds(2)))
                .isInstanceOf(ScannerException.class)
                .hasMessageContaining("timed out");

        long pid = Long.parseLong(Files.readString(dir.resolve("child.pid")).strip());
        Thread.sleep(300);
        assertThat(running(pid)).isFalse();
    }

    /** Linux: a killed process that nobody has reaped yet is a zombie (state Z); it no longer runs or uses memory. */
    private static boolean running(long pid) throws Exception {
        Path stat = Path.of("/proc/" + pid + "/stat");
        if (!Files.exists(stat)) {
            return false;
        }
        String s = Files.readString(stat);
        return s.charAt(s.lastIndexOf(')') + 2) != 'Z';
    }

    @Test
    void secretsInTheAppEnvironmentNeverReachTheTool() throws Exception {
        ProcessRunner.Result r = ProcessRunner.run(List.of("env"), dir, Duration.ofSeconds(10));
        List<String> names = r.stdout().lines().map(l -> l.substring(0, l.indexOf('='))).toList();
        assertThat(names).isSubsetOf("PATH", "HOME", "LANG", "LC_ALL", "PWD", "SHLVL", "_");
    }
}
