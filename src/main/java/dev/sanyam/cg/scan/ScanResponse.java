package dev.sanyam.cg.scan;

import java.time.OffsetDateTime;
import java.util.Map;
import java.util.UUID;

/** What the API shows for a scan. Built from the entity so internal fields never leak by accident. */
public record ScanResponse(
        UUID id, String filename, ScanStatus status, Integer fileCount, int attempts,
        String errorCode, String errorDetail,
        OffsetDateTime createdAt, OffsetDateTime startedAt, OffsetDateTime finishedAt,
        Map<String, String> links) {

    public static ScanResponse from(Scan s) {
        return new ScanResponse(s.getId(), s.getFilename(), s.getStatus(), s.getFileCount(), s.getAttempts(),
                s.getErrorCode(), s.getErrorDetail(), s.getCreatedAt(), s.getStartedAt(), s.getFinishedAt(),
                Map.of("self", "/api/scans/" + s.getId()));
    }
}
