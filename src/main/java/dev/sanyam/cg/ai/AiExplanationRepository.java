package dev.sanyam.cg.ai;

import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AiExplanationRepository extends JpaRepository<AiExplanation, UUID> {

    List<AiExplanation> findByFinding_Scan_Id(UUID scanId);
}
