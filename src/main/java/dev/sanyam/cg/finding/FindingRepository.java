package dev.sanyam.cg.finding;

import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface FindingRepository extends JpaRepository<Finding, UUID> {

    List<Finding> findByScan_Id(UUID scanId);
}
