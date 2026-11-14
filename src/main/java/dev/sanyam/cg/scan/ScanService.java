package dev.sanyam.cg.scan;

import dev.sanyam.cg.archive.ArchiveException;
import dev.sanyam.cg.user.User;
import java.io.IOException;
import java.io.InputStream;
import java.util.Locale;
import org.springframework.stereotype.Service;

@Service
public class ScanService {

    private final ScanRepository scans;
    private final ScanStorage storage;

    public ScanService(ScanRepository scans, ScanStorage storage) {
        this.scans = scans;
        this.storage = storage;
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
