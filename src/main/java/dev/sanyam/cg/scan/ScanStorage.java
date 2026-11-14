package dev.sanyam.cg.scan;

import dev.sanyam.cg.archive.ArchiveException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/** Where uploads and extraction folders live on disk, one of each per scan id. */
@Component
public class ScanStorage {

    public static final long MAX_UPLOAD_BYTES = 20L * 1024 * 1024;

    private static final Logger log = LoggerFactory.getLogger(ScanStorage.class);
    private static final byte[] ZIP_MAGIC = {'P', 'K', 3, 4};
    private static final byte[] EMPTY_ZIP_MAGIC = {'P', 'K', 5, 6};

    private final Path root;

    public ScanStorage(@Value("${cg.storage-dir:${java.io.tmpdir}/cg}") String dir) {
        this.root = Path.of(dir).toAbsolutePath().normalize();
    }

    public record StoredArchive(long bytes, String sha256) {
    }

    public Path archivePath(UUID scanId) {
        return root.resolve("uploads").resolve(scanId + ".zip");
    }

    public Path workDir(UUID scanId) {
        return root.resolve("work").resolve(scanId.toString());
    }

    /** Streams the upload to disk. Stops at 20 MB, counting real bytes rather than trusting any header. */
    public StoredArchive save(UUID scanId, InputStream in) throws IOException {
        Path target = archivePath(scanId);
        Files.createDirectories(target.getParent());
        MessageDigest sha = sha256();
        long total = 0;
        try (OutputStream out = Files.newOutputStream(target, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
            byte[] head = in.readNBytes(4);
            if (!Arrays.equals(head, ZIP_MAGIC) && !Arrays.equals(head, EMPTY_ZIP_MAGIC)) {
                throw new ArchiveException("not_a_zip", "The file is not a ZIP archive.");
            }
            out.write(head);
            sha.update(head);
            total = head.length;
            byte[] buffer = new byte[8192];
            int n;
            while ((n = in.read(buffer)) != -1) {
                total += n;
                if (total > MAX_UPLOAD_BYTES) {
                    throw new ArchiveException("archive_too_large", "Uploads are limited to 20 MB.");
                }
                out.write(buffer, 0, n);
                sha.update(buffer, 0, n);
            }
        } catch (IOException | RuntimeException e) {
            Files.deleteIfExists(target);
            throw e;
        }
        return new StoredArchive(total, HexFormat.of().formatHex(sha.digest()));
    }

    public void deleteArchive(UUID scanId) {
        try {
            Files.deleteIfExists(archivePath(scanId));
        } catch (IOException e) {
            log.warn("Could not delete archive for scan {}", scanId, e);
        }
    }

    private static MessageDigest sha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);  // every JVM ships SHA-256
        }
    }
}
