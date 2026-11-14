package dev.sanyam.cg.finding;

import dev.sanyam.cg.ai.AiExplanation;
import dev.sanyam.cg.ai.AiExplanationRepository;
import dev.sanyam.cg.api.ApiException;
import dev.sanyam.cg.scan.ScanRepository;
import dev.sanyam.cg.security.TokenService;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Collectors;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
class FindingController {

    /** counts always cover the whole scan; items respect the filters. */
    public record FindingList(int total, Map<Severity, Long> counts, List<FindingResponse> items) {
    }

    private final ScanRepository scans;
    private final FindingRepository findings;
    private final AiExplanationRepository explanations;

    FindingController(ScanRepository scans, FindingRepository findings, AiExplanationRepository explanations) {
        this.scans = scans;
        this.findings = findings;
        this.explanations = explanations;
    }

    @GetMapping("/api/scans/{id}/findings")
    FindingList list(@AuthenticationPrincipal Jwt jwt, @PathVariable UUID id,
                     @RequestParam(required = false) Severity severity,
                     @RequestParam(required = false) String tool) {
        // ownership first: another user's scan id gets the same 404 as an id that doesn't exist
        scans.findByIdAndUser_Id(id, TokenService.userId(jwt)).orElseThrow(ApiException::scanNotFound);
        List<Finding> all = findings.findByScan_Id(id);
        Map<UUID, AiExplanation> ai = explanations.findByFinding_Scan_Id(id).stream()
                .collect(Collectors.toMap(AiExplanation::getFindingId, Function.identity()));
        Map<Severity, Long> counts = new EnumMap<>(Severity.class);
        for (Severity s : Severity.values()) {
            counts.put(s, all.stream().filter(f -> f.getSeverity() == s).count());
        }
        List<FindingResponse> items = all.stream()
                .filter(f -> severity == null || f.getSeverity() == severity)
                .filter(f -> tool == null || f.getTool().equalsIgnoreCase(tool))
                .sorted(Comparator.comparing(Finding::getSeverity).thenComparing(Finding::getFilePath)
                        .thenComparingInt(Finding::getStartLine))
                .map(f -> FindingResponse.from(f, ai.get(f.getId())))
                .toList();
        return new FindingList(all.size(), counts, items);
    }
}
