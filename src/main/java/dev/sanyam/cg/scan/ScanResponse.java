package dev.sanyam.cg.scan;

import dev.sanyam.cg.ai.LlmStatus;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Map;
import java.util.UUID;

/** What the API shows for a scan. Built from the entity so internal fields never leak by accident. */
public record ScanResponse(
        UUID id, String filename, ScanStatus status, Integer fileCount, int attempts,
        String errorCode, String errorDetail, String toolErrors, LlmStatus llmStatus,
        OffsetDateTime createdAt, OffsetDateTime startedAt, OffsetDateTime finishedAt,
        Map<String, String> links) {

    public static ScanResponse from(Scan s) {
        return new ScanResponse(s.getId(), s.getFilename(), s.getStatus(), s.getFileCount(), s.getAttempts(),
                s.getErrorCode(), s.getErrorDetail(), s.getToolErrors(), s.getLlmStatus(), utc(s.getCreatedAt()), utc(s.getStartedAt()),
                utc(s.getFinishedAt()),
                Map.of("self", "/api/scans/" + s.getId(), "findings", "/api/scans/" + s.getId() + "/findings"));
    }

    /** Always UTC in the API, whatever time zone the server or database uses. */
    private static OffsetDateTime utc(OffsetDateTime t) {
        return t == null ? null : t.withOffsetSameInstant(ZoneOffset.UTC);
    }
}
