package dev.sanyam.cg.finding;

import dev.sanyam.cg.api.ApiException;
import dev.sanyam.cg.scan.ScanRepository;
import dev.sanyam.cg.security.TokenService;
import java.util.UUID;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
class FindingController {

    private final ScanRepository scans;
    private final FindingService findings;

    FindingController(ScanRepository scans, FindingService findings) {
        this.scans = scans;
        this.findings = findings;
    }

    @GetMapping("/api/scans/{id}/findings")
    FindingService.ScanFindings list(@AuthenticationPrincipal Jwt jwt, @PathVariable UUID id,
                                     @RequestParam(required = false) Severity severity,
                                     @RequestParam(required = false) String tool) {
        // ownership first: another user's scan id gets the same 404 as an id that doesn't exist
        scans.findByIdAndUser_Id(id, TokenService.userId(jwt)).orElseThrow(ApiException::scanNotFound);
        return findings.forScan(id, severity, tool);
    }
}
