package dev.sanyam.cg.finding;

import dev.sanyam.cg.ai.AiExplanation;
import dev.sanyam.cg.ai.AiExplanationRepository;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Collectors;
import org.springframework.stereotype.Service;

/** Findings of one scan with their AI explanations, for both the API and the dashboard. Callers check ownership. */
@Service
public class FindingService {

    /** counts always cover the whole scan; items respect the filters. */
    public record ScanFindings(int total, Map<Severity, Long> counts, List<FindingResponse> items) {
    }

    private final FindingRepository findings;
    private final AiExplanationRepository explanations;

    public FindingService(FindingRepository findings, AiExplanationRepository explanations) {
        this.findings = findings;
        this.explanations = explanations;
    }

    public ScanFindings forScan(UUID scanId, Severity severity, String tool) {
        List<Finding> all = findings.findByScan_Id(scanId);
        Map<UUID, AiExplanation> ai = explanations.findByFinding_Scan_Id(scanId).stream()
                .collect(Collectors.toMap(AiExplanation::getFindingId, Function.identity()));
        List<FindingResponse> items = all.stream()
                .filter(f -> severity == null || f.getSeverity() == severity)
                .filter(f -> tool == null || f.getTool().equalsIgnoreCase(tool))
                .sorted(Comparator.comparing(Finding::getSeverity).thenComparing(Finding::getFilePath)
                        .thenComparingInt(Finding::getStartLine))
                .map(f -> FindingResponse.from(f, ai.get(f.getId())))
                .toList();
        return new ScanFindings(all.size(), countBySeverity(all), items);
    }

    /** Severity counts for many scans in one query, for the scan list. */
    public Map<UUID, Map<Severity, Long>> countsFor(List<UUID> scanIds) {
        Map<UUID, Map<Severity, Long>> result = new HashMap<>();
        for (UUID id : scanIds) {
            result.put(id, zeroCounts());
        }
        if (!scanIds.isEmpty()) {
            for (Object[] row : findings.countBySeverity(scanIds)) {
                result.get((UUID) row[0]).put((Severity) row[1], (Long) row[2]);
            }
        }
        return result;
    }

    private static Map<Severity, Long> countBySeverity(List<Finding> all) {
        Map<Severity, Long> counts = zeroCounts();
        all.forEach(f -> counts.merge(f.getSeverity(), 1L, Long::sum));
        return counts;
    }

    private static Map<Severity, Long> zeroCounts() {
        Map<Severity, Long> counts = new EnumMap<>(Severity.class);
        for (Severity s : Severity.values()) {
            counts.put(s, 0L);
        }
        return counts;
    }
}
