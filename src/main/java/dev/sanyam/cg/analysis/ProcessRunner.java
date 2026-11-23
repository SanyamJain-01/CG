package dev.sanyam.cg.analysis;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * Runs one scanner as a separate process. It gets an argument list (never a shell), a timeout, and an almost empty
 * environment, so database passwords and API keys in this app's environment can't reach it.
 * ponytail: no memory limit here; the container's memory limit (M5) is the cap.
 */
final class ProcessRunner {

    record Result(int exitCode, String stdout, String stderr) {
    }

    private ProcessRunner() {
    }

    static Result run(List<String> command, Path workingDir, Duration timeout) throws IOException, InterruptedException {
        Path out = Files.createTempFile("cg-stdout", ".txt");
        Path err = Files.createTempFile("cg-stderr", ".txt");
        try {
            ProcessBuilder builder = new ProcessBuilder(command)
                    .directory(workingDir.toFile())
                    .redirectOutput(out.toFile())   // files, not pipes: a chatty tool can't block on a full buffer
                    .redirectError(err.toFile());
            Map<String, String> env = builder.environment();
            String path = env.get("PATH");
            String home = env.get("HOME");
            env.clear();
            if (path != null) {
                env.put("PATH", path);
            }
            if (home != null) {
                env.put("HOME", home);  // Semgrep keeps its settings there
            }
            env.put("LANG", "C.UTF-8");  // Python-based tools refuse to start without a UTF-8 locale
            env.put("LC_ALL", "C.UTF-8");
            Process process = builder.start();
            if (!process.waitFor(timeout.toSeconds(), TimeUnit.SECONDS)) {
                // children first: Semgrep starts semgrep-core, which would keep running if only the parent died
                process.descendants().forEach(ProcessHandle::destroyForcibly);
                process.destroyForcibly();
                throw new ScannerException("timed out after " + timeout.toSeconds() + " s");
            }
            return new Result(process.exitValue(), read(out), read(err));
        } finally {
            Files.deleteIfExists(out);
            Files.deleteIfExists(err);
        }
    }

    /** Lenient decoding: a tool printing odd bytes must not crash the scan. */
    private static String read(Path file) throws IOException {
        return new String(Files.readAllBytes(file), StandardCharsets.UTF_8);
    }
}
