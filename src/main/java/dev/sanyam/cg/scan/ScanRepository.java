package dev.sanyam.cg.scan;

import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ScanRepository extends JpaRepository<Scan, UUID> {

    /** A user's latest scans. Every scan query takes the owner's id: that's how one user never sees another's. */
    List<Scan> findTop20ByUser_IdOrderByCreatedAtDesc(UUID userId);

    Optional<Scan> findByIdAndUser_Id(UUID id, UUID userId);
}
