package dev.sanyam.cg.web;

import dev.sanyam.cg.api.ApiException;
import dev.sanyam.cg.archive.ArchiveException;
import dev.sanyam.cg.finding.FindingService;
import dev.sanyam.cg.finding.FindingResponse;
import dev.sanyam.cg.finding.Severity;
import dev.sanyam.cg.scan.Scan;
import dev.sanyam.cg.scan.ScanRepository;
import dev.sanyam.cg.scan.ScanResponse;
import dev.sanyam.cg.scan.ScanService;
import dev.sanyam.cg.scan.ScanStatus;
import dev.sanyam.cg.scan.ScanStorage;
import dev.sanyam.cg.user.AuthService;
import dev.sanyam.cg.user.User;
import dev.sanyam.cg.user.UserRepository;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.InputStream;
import java.time.OffsetDateTime;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.data.domain.Limit;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

/** Server-rendered pages. Same rules as the API: every query is scoped to the logged-in user. */
@Controller
class DashboardController {

    private final ScanRepository scans;
    private final ScanService scanService;
    private final ScanStorage storage;
    private final FindingService findings;
    private final UserRepository users;
    private final AuthService auth;

    DashboardController(ScanRepository scans, ScanService scanService, ScanStorage storage, FindingService findings,
                        UserRepository users, AuthService auth) {
        this.scans = scans;
        this.scanService = scanService;
        this.storage = storage;
        this.findings = findings;
        this.users = users;
        this.auth = auth;
    }

    @GetMapping("/login")
    String login() {
        return "login";
    }

    @GetMapping("/register")
    String registerForm() {
        return "register";
    }

    @PostMapping("/register")
    String register(@RequestParam String email, @RequestParam String password, Model model) {
        String error = password.length() < 12 || password.length() > 128 ? "Password must be 12 to 128 characters."
                : !email.contains("@") || email.length() > 254 ? "Enter a valid email address." : null;
        if (error == null) {
            try {
                auth.register(email, password);
                return "redirect:/login?registered";
            } catch (ApiException e) {
                error = e.getMessage();
            }
        }
        model.addAttribute("error", error);
        model.addAttribute("email", email);
        return "register";
    }

    @GetMapping("/")
    String scans(Authentication who, Model model) {
        UUID userId = userId(who);
        List<ScanResponse> list = scans.findByUser_IdAndCreatedAtBeforeOrderByCreatedAtDesc(
                userId, OffsetDateTime.now().plusYears(1), Limit.of(50))
                .stream().map(ScanResponse::from).toList();
        model.addAttribute("email", users.findById(userId).map(User::getEmail).orElse(""));
        model.addAttribute("scans", list);
        // templates look counts up by plain strings: Thymeleaf blocks static class access like T(Severity)
        Map<String, Map<String, Long>> counts = new HashMap<>();
        findings.countsFor(list.stream().map(ScanResponse::id).toList())
                .forEach((scanId, bySeverity) -> counts.put(scanId.toString(), byName(bySeverity)));
        model.addAttribute("counts", counts);
        return "scans";
    }

    @PostMapping("/scans")
    String upload(Authentication who, @RequestParam("file") MultipartFile file, RedirectAttributes flash)
            throws IOException {
        UUID userId = userId(who);
        try {
            scanService.checkUploadLimit(userId);
            User user = users.findById(userId).orElseThrow();
            Scan scan;
            try (InputStream in = file.getInputStream()) {
                scan = scanService.submit(user, file.getOriginalFilename(), in);
            }
            return "redirect:/scans/" + scan.getId();
        } catch (ArchiveException | ApiException e) {
            flash.addFlashAttribute("error", e.getMessage());
            return "redirect:/";
        }
    }

    @GetMapping("/scans/{id}")
    String scan(Authentication who, @PathVariable UUID id, Model model) {
        Scan scan = owned(who, id);
        FindingService.ScanFindings result = findings.forScan(id, null, null);
        model.addAttribute("scan", ScanResponse.from(scan));
        model.addAttribute("findings", result.items());
        model.addAttribute("counts", byName(result.counts()));
        model.addAttribute("inProgress", scan.getStatus() == ScanStatus.QUEUED || scan.getStatus() == ScanStatus.RUNNING);
        model.addAttribute("disclaimer", FindingResponse.DISCLAIMER);
        return "scan";
    }

    @PostMapping("/scans/{id}/delete")
    String delete(Authentication who, @PathVariable UUID id) {
        scans.delete(owned(who, id));
        storage.deleteArchive(id);
        return "redirect:/";
    }

    /** An HTML page, not the API's JSON, when a scan doesn't exist or isn't yours. */
    @ExceptionHandler(ApiException.class)
    String notFound(ApiException e, HttpServletResponse response, Model model) {
        response.setStatus(e.getStatus().value());
        model.addAttribute("message", e.getMessage());
        return "message";
    }

    private Scan owned(Authentication who, UUID id) {
        return scans.findByIdAndUser_Id(id, userId(who)).orElseThrow(ApiException::scanNotFound);
    }

    private static Map<String, Long> byName(Map<Severity, Long> counts) {
        Map<String, Long> named = new LinkedHashMap<>();
        counts.forEach((severity, n) -> named.put(severity.name(), n));
        return named;
    }

    private static UUID userId(Authentication who) {
        return UUID.fromString(who.getName());
    }
}
