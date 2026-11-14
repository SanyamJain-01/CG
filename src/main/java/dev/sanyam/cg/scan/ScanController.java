package dev.sanyam.cg.scan;

import dev.sanyam.cg.api.ApiException;
import dev.sanyam.cg.security.RateLimiter;
import dev.sanyam.cg.security.TokenService;
import dev.sanyam.cg.user.User;
import dev.sanyam.cg.user.UserRepository;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.UUID;
import org.springframework.data.domain.Limit;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

/** Every query here is scoped to the caller's user id, so another user's scan is simply "not found". */
@RestController
@RequestMapping("/api/scans")
class ScanController {

    static final int MAX_UPLOADS = 10;
    static final Duration UPLOAD_WINDOW = Duration.ofHours(1);

    public record ScanPage(List<ScanResponse> items, OffsetDateTime nextCursor) {
    }

    private final ScanService service;
    private final ScanRepository scans;
    private final ScanStorage storage;
    private final UserRepository users;
    private final RateLimiter limiter;

    ScanController(ScanService service, ScanRepository scans, ScanStorage storage, UserRepository users,
                   RateLimiter limiter) {
        this.service = service;
        this.scans = scans;
        this.storage = storage;
        this.users = users;
        this.limiter = limiter;
    }

    @PostMapping(consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    ResponseEntity<ScanResponse> upload(@AuthenticationPrincipal Jwt jwt, @RequestParam("file") MultipartFile file)
            throws IOException {
        UUID userId = TokenService.userId(jwt);
        String key = "upload:" + userId;
        long wait = limiter.retryAfter(key, MAX_UPLOADS, UPLOAD_WINDOW);
        if (wait > 0) {
            throw ApiException.rateLimited(wait);
        }
        limiter.record(key, UPLOAD_WINDOW);
        Scan scan;
        try (InputStream in = file.getInputStream()) {
            User user = users.findById(userId).orElseThrow(() -> new ApiException(
                    HttpStatus.UNAUTHORIZED, "token_invalid", "This account no longer exists."));
            scan = service.submit(user, file.getOriginalFilename(), in);
        }
        return ResponseEntity.accepted().location(URI.create("/api/scans/" + scan.getId())).body(ScanResponse.from(scan));
    }

    /** Newest first. Pass the returned nextCursor as "before" to get the next page. */
    @GetMapping
    ScanPage list(@AuthenticationPrincipal Jwt jwt,
                  @RequestParam(defaultValue = "20") int limit,
                  @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) OffsetDateTime before) {
        int size = Math.clamp(limit, 1, 100);
        OffsetDateTime cursor = before != null ? before : OffsetDateTime.now().plusYears(1);
        // ponytail: two scans created in the same microsecond could straddle a page; add id as a tie-breaker if that ever matters
        List<ScanResponse> items = scans.findByUser_IdAndCreatedAtBeforeOrderByCreatedAtDesc(
                TokenService.userId(jwt), cursor, Limit.of(size)).stream().map(ScanResponse::from).toList();
        OffsetDateTime next = items.size() == size ? items.getLast().createdAt() : null;
        return new ScanPage(items, next);
    }

    @GetMapping("/{id}")
    ScanResponse get(@AuthenticationPrincipal Jwt jwt, @PathVariable UUID id) {
        return ScanResponse.from(owned(jwt, id));
    }

    @DeleteMapping("/{id}")
    ResponseEntity<Void> delete(@AuthenticationPrincipal Jwt jwt, @PathVariable UUID id) {
        scans.delete(owned(jwt, id));
        storage.deleteArchive(id);
        return ResponseEntity.noContent().build();
    }

    private Scan owned(Jwt jwt, UUID id) {
        return scans.findByIdAndUser_Id(id, TokenService.userId(jwt)).orElseThrow(ApiException::scanNotFound);
    }
}
