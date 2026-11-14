package dev.sanyam.cg.scan;

import dev.sanyam.cg.api.ApiException;
import dev.sanyam.cg.archive.ArchiveException;
import dev.sanyam.cg.security.RateLimiter;
import dev.sanyam.cg.user.User;
import java.io.IOException;
import java.io.InputStream;
import java.time.Duration;
import java.util.Locale;
import java.util.UUID;
import org.springframework.stereotype.Service;

@Service
public class ScanService {

    static final int MAX_UPLOADS = 10;
    static final Duration UPLOAD_WINDOW = Duration.ofHours(1);

    private final ScanRepository scans;
    private final ScanStorage storage;
    private final RateLimiter limiter;

    public ScanService(ScanRepository scans, ScanStorage storage, RateLimiter limiter) {
        this.scans = scans;
        this.storage = storage;
        this.limiter = limiter;
    }

    /** 10 uploads per user per hour, shared by the API and the dashboard. Counts this upload. */
    public void checkUploadLimit(UUID userId) {
        String key = "upload:" + userId;
        long wait = limiter.retryAfter(key, MAX_UPLOADS, UPLOAD_WINDOW);
        if (wait > 0) {
            throw ApiException.rateLimited(wait);
        }
        limiter.record(key, UPLOAD_WINDOW);
    }

    /** Stores the upload and queues a scan. The worker does the slow part, so this returns quickly. */
    public Scan submit(User user, String originalFilename, InputStream content) throws IOException {
        String name = cleanFilename(originalFilename);
        if (!name.toLowerCase(Locale.ROOT).endsWith(".zip")) {
            throw new ArchiveException("not_a_zip", "Only .zip files are accepted.");
        }
        Scan scan = new Scan(user, name);
        ScanStorage.StoredArchive stored = storage.save(scan.getId(), content);
        scan.attachArchive(stored.sha256(), stored.bytes());
        try {
            return scans.save(scan);
        } catch (RuntimeException e) {
            storage.deleteArchive(scan.getId());
            throw e;
        }
    }

    /** Keeps only the file name: browsers can send full paths, and names end up in the UI. */
    static String cleanFilename(String original) {
        String name = original == null ? "" : original;
        name = name.substring(Math.max(name.lastIndexOf('/'), name.lastIndexOf('\\')) + 1);
        name = name.replaceAll("\\p{Cntrl}", "").strip();
        return name.length() > 200 ? name.substring(name.length() - 200) : name;
    }
}
