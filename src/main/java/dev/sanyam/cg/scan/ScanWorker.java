package dev.sanyam.cg.scan;

import dev.sanyam.cg.ai.AiExplanation;
import dev.sanyam.cg.ai.AiExplanationRepository;
import dev.sanyam.cg.ai.Explainer;
import dev.sanyam.cg.analysis.AnalysisResult;
import dev.sanyam.cg.analysis.Evidence;
import dev.sanyam.cg.analysis.Scanners;
import dev.sanyam.cg.archive.ArchiveException;
import dev.sanyam.cg.archive.ExtractResult;
import dev.sanyam.cg.archive.SafeExtractor;
import dev.sanyam.cg.finding.Finding;
import dev.sanyam.cg.finding.FindingRepository;
import jakarta.annotation.PreDestroy;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.util.FileSystemUtils;

/**
 * Takes one scan from the queue and processes it. Claiming is a short transaction; the slow work runs outside it,
 * with a heartbeat every 10 s. If this process dies, the heartbeat goes stale and another run picks the scan up.
 */
@Component
public class ScanWorker {

    static final Duration STALE_AFTER = Duration.ofSeconds(60);
    static final Duration HEARTBEAT_EVERY = Duration.ofSeconds(10);
    static final int MAX_ATTEMPTS = 3;

    private static final Logger log = LoggerFactory.getLogger(ScanWorker.class);

    private final ScanRepository scans;
    private final ScanStorage storage;
    private final SafeExtractor extractor;
    private final Scanners scanners;
    private final FindingRepository findings;
    private final Explainer explainer;
    private final AiExplanationRepository explanations;
    private final TransactionTemplate tx;
    private final ScheduledExecutorService heartbeats = Executors.newSingleThreadScheduledExecutor();

    public ScanWorker(ScanRepository scans, ScanStorage storage, SafeExtractor extractor, Scanners scanners,
                      FindingRepository findings, Explainer explainer, AiExplanationRepository explanations,
                      TransactionTemplate tx) {
        this.scans = scans;
        this.storage = storage;
        this.extractor = extractor;
        this.scanners = scanners;
        this.findings = findings;
        this.explainer = explainer;
        this.explanations = explanations;
        this.tx = tx;
    }

    /** Processes the next scan, if any. Returns false when the queue had nothing to do. */
    public boolean processNext() {
        UUID id = tx.execute(status -> claim());
        if (id == null) {
            return false;
        }
        process(id);
        return true;
    }

    private UUID claim() {
        Scan scan = scans.lockNextClaimable(OffsetDateTime.now().minus(STALE_AFTER)).orElse(null);
        if (scan == null) {
            return null;
        }
        if (scan.getAttempts() >= MAX_ATTEMPTS) {  // it kept dying mid-scan; stop retrying
            scan.fail("retries_exhausted", "The scan was interrupted " + MAX_ATTEMPTS + " times.");
            storage.deleteArchive(scan.getId());
            log.warn("scan.retries_exhausted id={}", scan.getId());
            return null;
        }
        scan.startAttempt();  // saved when the transaction commits; RUNNING + fresh heartbeat keeps others away
        log.info("scan.started id={} attempt={}", scan.getId(), scan.getAttempts());
        return scan.getId();
    }

    private void process(UUID id) {
        ScheduledFuture<?> beat = heartbeats.scheduleAtFixedRate(() -> heartbeat(id),
                HEARTBEAT_EVERY.toSeconds(), HEARTBEAT_EVERY.toSeconds(), TimeUnit.SECONDS);
        Path work = storage.workDir(id);
        try {
            if (!Files.isRegularFile(storage.archivePath(id))) {
                // hosts with temporary disks (Render's free tier) lose uploads on restart; say so instead of "damaged"
                throw new ArchiveException("upload_lost",
                        "The uploaded file was lost when the server restarted. Please upload it again.");
            }
            FileSystemUtils.deleteRecursively(work);  // leftovers from a crashed attempt
            Files.createDirectories(work);
            ExtractResult result = extractor.extract(storage.archivePath(id), work);
            AnalysisResult analysis = scanners.scan(work);
            List<Evidence.Draft> drafts = Evidence.attach(analysis.findings(), work);  // before work is deleted
            Explainer.Result ai = explainer.explain(drafts);  // network call, outside any transaction
            List<String> problems = new ArrayList<>(analysis.errors());
            if (ai.error() != null) {
                problems.add("llm: " + ai.error());
            }
            String toolErrors = problems.isEmpty() ? null : String.join("; ", problems);
            // findings and their explanations are saved together, so a scan is never half-finished
            finish(id, scan -> {
                scan.succeed(result.filesWritten(), toolErrors, ai.status());
                List<Finding> saved = findings.saveAll(drafts.stream().map(d -> new Finding(scan, d)).toList());
                List<AiExplanation> notes = new ArrayList<>();
                ai.notes().forEach((index, note) ->
                        notes.add(new AiExplanation(saved.get(index), note, ai.model(), Explainer.PROMPT_VERSION)));
                explanations.saveAll(notes);
            });
            log.info("scan.finished id={} files={} findings={} explained={} llm={} tool_errors={}", id,
                    result.filesWritten(), drafts.size(), ai.notes().size(), ai.status(), toolErrors);
        } catch (ArchiveException e) {
            finish(id, scan -> scan.fail(e.getCode(), e.getMessage()));
            log.info("scan.rejected id={} code={}", id, e.getCode());
        } catch (Exception e) {
            finish(id, scan -> scan.fail("internal_error", "Unexpected error while scanning."));
            log.error("scan.failed id={}", id, e);
        } finally {
            beat.cancel(false);
            deleteQuietly(work);
        }
    }

    private void finish(UUID id, Consumer<Scan> outcome) {
        // the user may have deleted the scan while it ran; then there is nothing left to update
        tx.executeWithoutResult(status -> scans.findById(id).ifPresent(outcome));
        storage.deleteArchive(id);  // only after a final result; a crash keeps it for the retry
    }

    private void heartbeat(UUID id) {
        try {
            tx.executeWithoutResult(status -> scans.heartbeat(id, OffsetDateTime.now()));
        } catch (RuntimeException e) {
            log.warn("Heartbeat failed for scan {}", id, e);  // a thrown error would silently stop the schedule
        }
    }

    private static void deleteQuietly(Path dir) {
        try {
            FileSystemUtils.deleteRecursively(dir);
        } catch (IOException e) {
            log.warn("Could not delete {}", dir, e);
        }
    }

    @PreDestroy
    void shutdown() {
        heartbeats.shutdownNow();
    }
}
