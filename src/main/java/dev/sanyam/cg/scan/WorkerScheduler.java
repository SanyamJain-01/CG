package dev.sanyam.cg.scan;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;

/** Polls the queue every 2 s. Tests turn it off with cg.worker.enabled=false and call the worker directly. */
@Configuration
@EnableScheduling
@ConditionalOnProperty(name = "cg.worker.enabled", havingValue = "true", matchIfMissing = true)
class WorkerScheduler {

    private final ScanWorker worker;

    WorkerScheduler(ScanWorker worker) {
        this.worker = worker;
    }

    @Scheduled(fixedDelayString = "${cg.worker.poll-ms:2000}")
    void poll() {
        while (worker.processNext()) {
            // keep going until the queue is empty
        }
    }
}
