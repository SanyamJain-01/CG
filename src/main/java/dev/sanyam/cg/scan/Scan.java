package dev.sanyam.cg.scan;

import dev.sanyam.cg.user.User;
import jakarta.persistence.*;
import java.time.OffsetDateTime;
import java.util.UUID;

@Entity
@Table(name = "scans")
public class Scan {

    @Id
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, columnDefinition = "text")
    private ScanStatus status;

    @Column(nullable = false, columnDefinition = "text")
    private String filename;

    @Column(name = "archive_sha256", columnDefinition = "text")
    private String archiveSha256;

    @Column(name = "archive_bytes")
    private Long archiveBytes;

    @Column(name = "file_count")
    private Integer fileCount;

    @Column(nullable = false)
    private int attempts;

    @Column(name = "heartbeat_at", columnDefinition = "timestamptz")
    private OffsetDateTime heartbeatAt;

    @Column(name = "error_code", columnDefinition = "text")
    private String errorCode;

    @Column(name = "error_detail", columnDefinition = "text")
    private String errorDetail;

    @Column(name = "created_at", nullable = false, columnDefinition = "timestamptz")
    private OffsetDateTime createdAt;

    @Column(name = "started_at", columnDefinition = "timestamptz")
    private OffsetDateTime startedAt;

    @Column(name = "finished_at", columnDefinition = "timestamptz")
    private OffsetDateTime finishedAt;

    protected Scan() {
        // for JPA
    }

    public Scan(User user, String filename) {
        this.id = UUID.randomUUID();
        this.user = user;
        this.filename = filename;
        this.status = ScanStatus.QUEUED;
        this.createdAt = OffsetDateTime.now();
    }

    /** The worker picked this scan up. The database rejects a 4th attempt (CHECK attempts <= 3). */
    public void startAttempt() {
        attempts++;
        status = ScanStatus.RUNNING;
        startedAt = OffsetDateTime.now();
        heartbeatAt = startedAt;
    }

    public void succeed(int fileCount) {
        this.fileCount = fileCount;
        finish(ScanStatus.SUCCEEDED);
    }

    public void fail(String errorCode, String errorDetail) {
        this.errorCode = errorCode;
        this.errorDetail = errorDetail;
        finish(ScanStatus.FAILED);
    }

    private void finish(ScanStatus result) {
        status = result;
        finishedAt = OffsetDateTime.now();
    }

    public UUID getId() { return id; }
    public User getUser() { return user; }
    public ScanStatus getStatus() { return status; }
    public String getFilename() { return filename; }
    public int getAttempts() { return attempts; }
    public Integer getFileCount() { return fileCount; }
    public String getErrorCode() { return errorCode; }
    public OffsetDateTime getCreatedAt() { return createdAt; }
    public OffsetDateTime getStartedAt() { return startedAt; }
    public OffsetDateTime getFinishedAt() { return finishedAt; }
}
