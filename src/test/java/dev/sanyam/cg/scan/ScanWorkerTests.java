package dev.sanyam.cg.scan;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

import dev.sanyam.cg.TestcontainersConfiguration;
import dev.sanyam.cg.analysis.AnalysisResult;
import dev.sanyam.cg.analysis.RawFinding;
import dev.sanyam.cg.analysis.Scanners;
import dev.sanyam.cg.archive.ArchiveException;
import dev.sanyam.cg.archive.TestZips;
import dev.sanyam.cg.finding.Finding;
import dev.sanyam.cg.finding.FindingRepository;
import dev.sanyam.cg.finding.Severity;
import dev.sanyam.cg.user.User;
import dev.sanyam.cg.user.UserRepository;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Upload, queue and worker against a real Postgres. The scheduler is off (tests call the worker themselves) and the
 * scanners are mocked, so these tests are fast and work offline; RealScannersTests covers the real tools.
 */
@SpringBootTest(properties = {"cg.worker.enabled=false", "cg.storage-dir=${java.io.tmpdir}/cg-test"})
@Import(TestcontainersConfiguration.class)
class ScanWorkerTests {

    @Autowired ScanService service;
    @Autowired ScanWorker worker;
    @Autowired ScanRepository scans;
    @Autowired ScanStorage storage;
    @Autowired UserRepository users;
    @Autowired JdbcTemplate jdbc;
    @Autowired TransactionTemplate tx;
    @Autowired FindingRepository findings;
    @MockitoBean Scanners scanners;

    @TempDir Path tmp;
    User user;

    @BeforeEach
    void setUp() {
        jdbc.update("DELETE FROM scans");
        jdbc.update("DELETE FROM users");
        user = users.save(new User("dev@example.com", "hash"));
        when(scanners.scan(any())).thenReturn(AnalysisResult.empty());
    }

    @Test
    void findingsAreSavedWithTheirCodeAndToolErrorsAreRecorded() throws IOException {
        when(scanners.scan(any())).thenReturn(new AnalysisResult(
                List.of(new RawFinding("bandit", "B602", Severity.HIGH, "app.py", 2, 2, "shell=True")),
                List.of("semgrep: not installed")));
        Scan queued = submit(TestZips.create(tmp.resolve("a.zip")).file("app.py", "import subprocess\nsubprocess.call(c, shell=True)\n"));

        worker.processNext();

        Scan done = reload(queued);
        assertThat(done.getStatus()).isEqualTo(ScanStatus.SUCCEEDED);  // one missing tool doesn't fail the scan
        assertThat(done.getToolErrors()).isEqualTo("semgrep: not installed");
        List<Finding> saved = findings.findByScan_Id(done.getId());
        assertThat(saved).hasSize(1);
        assertThat(saved.getFirst().getSnippet()).contains("shell=True");  // evidence kept after files are deleted
    }

    @Test
    void validArchiveIsQueuedThenScanned() throws IOException {
        Scan queued = submit(TestZips.create(tmp.resolve("a.zip")).file("app.py", "x = 1").file("src/Main.java", "class Main {}"));

        assertThat(queued.getStatus()).isEqualTo(ScanStatus.QUEUED);
        assertThat(queued.getArchiveSha256()).hasSize(64);
        assertThat(worker.processNext()).isTrue();

        Scan done = reload(queued);
        assertThat(done.getStatus()).isEqualTo(ScanStatus.SUCCEEDED);
        assertThat(done.getFileCount()).isEqualTo(2);
        assertThat(done.getAttempts()).isEqualTo(1);
        assertThat(storage.archivePath(done.getId())).doesNotExist();  // upload deleted after the scan
        assertThat(storage.workDir(done.getId())).doesNotExist();
        assertThat(worker.processNext()).isFalse();  // queue is empty
    }

    @Test
    void maliciousArchiveFailsWithItsCode() throws IOException {
        Scan queued = submit(TestZips.create(tmp.resolve("a.zip")).file("../evil.py", "pwned"));

        worker.processNext();

        Scan done = reload(queued);
        assertThat(done.getStatus()).isEqualTo(ScanStatus.FAILED);
        assertThat(done.getErrorCode()).isEqualTo("unsafe_archive_path");
    }

    @Test
    void scanWhoseWorkerDiedIsRetried() throws IOException {
        Scan queued = submit(TestZips.create(tmp.resolve("a.zip")).file("app.py", "x = 1"));
        simulateCrashedAttempt(queued.getId(), 1);

        worker.processNext();

        Scan done = reload(queued);
        assertThat(done.getStatus()).isEqualTo(ScanStatus.SUCCEEDED);
        assertThat(done.getAttempts()).isEqualTo(2);
    }

    @Test
    void retriesStopAfterThreeAttempts() throws IOException {
        Scan queued = submit(TestZips.create(tmp.resolve("a.zip")).file("app.py", "x = 1"));
        simulateCrashedAttempt(queued.getId(), 3);

        worker.processNext();

        Scan done = reload(queued);
        assertThat(done.getStatus()).isEqualTo(ScanStatus.FAILED);
        assertThat(done.getErrorCode()).isEqualTo("retries_exhausted");
    }

    @Test
    void twoWorkersNeverGetTheSameScan() throws Exception {
        Scan first = submit(TestZips.create(tmp.resolve("a.zip")).file("a.py", "1"));
        Scan second = submit(TestZips.create(tmp.resolve("b.zip")).file("b.py", "2"));
        jdbc.update("UPDATE scans SET created_at = now() - interval '1 minute' WHERE id = ?", first.getId());

        CountDownLatch locked = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        ExecutorService otherWorker = Executors.newSingleThreadExecutor();
        Future<UUID> held = otherWorker.submit(() -> tx.execute(status -> {
            UUID id = scans.lockNextClaimable(OffsetDateTime.now()).orElseThrow().getId();
            locked.countDown();
            awaitQuietly(release);  // keep the row locked while the main thread looks for work
            return id;
        }));
        assertThat(locked.await(10, TimeUnit.SECONDS)).isTrue();

        UUID mine = tx.execute(status -> scans.lockNextClaimable(OffsetDateTime.now()).orElseThrow().getId());
        release.countDown();

        assertThat(held.get(10, TimeUnit.SECONDS)).isEqualTo(first.getId());
        assertThat(mine).isEqualTo(second.getId());  // skipped the locked row instead of waiting or taking it
        otherWorker.shutdown();
    }

    @Test
    void rejectsFilesThatAreNotZips() {
        InputStream text = new ByteArrayInputStream("hello".getBytes(StandardCharsets.UTF_8));
        assertThatThrownBy(() -> service.submit(user, "notes.txt", text))
                .hasFieldOrPropertyWithValue("code", "not_a_zip");

        InputStream disguised = new ByteArrayInputStream("hello".getBytes(StandardCharsets.UTF_8));
        assertThatThrownBy(() -> service.submit(user, "renamed.zip", disguised))
                .hasFieldOrPropertyWithValue("code", "not_a_zip");

        assertThat(scans.count()).isZero();
    }

    @Test
    void rejectsUploadsOver20Mb() {
        byte[] big = new byte[(int) ScanStorage.MAX_UPLOAD_BYTES + 1024];
        System.arraycopy(new byte[] {'P', 'K', 3, 4}, 0, big, 0, 4);

        assertThatThrownBy(() -> service.submit(user, "big.zip", new ByteArrayInputStream(big)))
                .isInstanceOf(ArchiveException.class)
                .hasFieldOrPropertyWithValue("code", "archive_too_large");
        assertThat(scans.count()).isZero();
    }

    private Scan submit(TestZips zip) throws IOException {
        zip.close();
        Path file = Files.list(tmp).filter(p -> p.toString().endsWith(".zip")).sorted().reduce((a, b) -> b).orElseThrow();
        try (InputStream in = Files.newInputStream(file)) {
            return service.submit(user, "repo.zip", in);
        } finally {
            Files.delete(file);
        }
    }

    private void simulateCrashedAttempt(UUID id, int attempts) {
        jdbc.update("""
                UPDATE scans SET status = 'RUNNING', attempts = ?, started_at = now() - interval '5 minutes',
                                 heartbeat_at = now() - interval '5 minutes'
                WHERE id = ?""", attempts, id);
    }

    private Scan reload(Scan scan) {
        return scans.findById(scan.getId()).orElseThrow();
    }

    private static void awaitQuietly(CountDownLatch latch) {
        try {
            latch.await(10, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
