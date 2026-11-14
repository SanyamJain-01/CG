package dev.sanyam.cg.scan;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface ScanRepository extends JpaRepository<Scan, UUID> {

    /** A user's latest scans. Every scan query takes the owner's id: that's how one user never sees another's. */
    List<Scan> findTop20ByUser_IdOrderByCreatedAtDesc(UUID userId);

    Optional<Scan> findByIdAndUser_Id(UUID id, UUID userId);

    /**
     * Locks the oldest scan that needs work: queued, or running with a heartbeat older than staleBefore (its worker
     * died). SKIP LOCKED makes a second worker skip a row the first has locked instead of waiting for it, so two
     * workers can never take the same scan. Must run inside a transaction; the lock ends when it commits.
     */
    @Query(value = """
            SELECT * FROM scans
            WHERE status = 'QUEUED' OR (status = 'RUNNING' AND heartbeat_at < :staleBefore)
            ORDER BY created_at
            LIMIT 1
            FOR UPDATE SKIP LOCKED
            """, nativeQuery = true)
    Optional<Scan> lockNextClaimable(@Param("staleBefore") OffsetDateTime staleBefore);

    @Modifying
    @Query("UPDATE Scan s SET s.heartbeatAt = :now WHERE s.id = :id AND s.status = dev.sanyam.cg.scan.ScanStatus.RUNNING")
    int heartbeat(@Param("id") UUID id, @Param("now") OffsetDateTime now);
}
