package dev.sanyam.cg.finding;

import java.util.Collection;
import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface FindingRepository extends JpaRepository<Finding, UUID> {

    List<Finding> findByScan_Id(UUID scanId);

    /** Rows of (scan id, severity, count). One query for a whole page of scans instead of one per scan. */
    @Query("SELECT f.scan.id, f.severity, COUNT(f) FROM Finding f WHERE f.scan.id IN :scanIds GROUP BY f.scan.id, f.severity")
    List<Object[]> countBySeverity(@Param("scanIds") Collection<UUID> scanIds);
}
