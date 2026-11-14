package dev.sanyam.cg.archive;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import org.apache.commons.compress.archivers.zip.ZipArchiveEntry;
import org.apache.commons.compress.archivers.zip.ZipFile;

/**
 * Extracts an untrusted ZIP into an empty folder. Every entry is checked before anything is written, and the
 * bytes actually written are counted, because a ZIP's own size fields can lie. Uploaded code is never executed.
 */
public class SafeExtractor {

    /** Small files compress very well legitimately; the ratio check only applies above this size. */
    static final long RATIO_FLOOR_BYTES = 1024 * 1024;

    private static final Set<String> SUPPORTED_EXTENSIONS = Set.of(
            "py", "java", "kt", "js", "jsx", "ts", "tsx", "go", "rb", "php", "cs", "c", "cpp", "h", "rs",
            "sql", "sh", "yml", "yaml", "json", "xml", "properties", "toml", "ini", "cfg", "conf", "env",
            "txt", "md", "html", "gradle", "tf");

    private final ArchiveLimits limits;

    public SafeExtractor(ArchiveLimits limits) {
        this.limits = limits;
    }

    public ExtractResult extract(Path archive, Path target) {
        Path root;
        try {
            root = target.toRealPath();
        } catch (IOException e) {
            throw new IllegalStateException("Extraction folder must exist: " + target, e);
        }
        try (ZipFile zip = ZipFile.builder().setPath(archive).get()) {
            List<ZipArchiveEntry> entries = Collections.list(zip.getEntries());
            checkBeforeWriting(entries);
            return write(zip, entries, root);
        } catch (IOException e) {
            throw new ArchiveException("invalid_archive", "The archive is damaged or is not a valid ZIP.");
        }
    }

    private void checkBeforeWriting(List<ZipArchiveEntry> entries) {
        if (entries.size() > limits.maxEntries()) {
            throw new ArchiveException("too_many_files",
                    "The archive has more than " + limits.maxEntries() + " entries.");
        }
        long declaredTotal = 0;
        for (ZipArchiveEntry entry : entries) {
            if (isUnsafeName(entry.getName())) {
                throw new ArchiveException("unsafe_archive_path", "Unsafe path in archive: " + entry.getName());
            }
            if (entry.isUnixSymlink()) {
                throw new ArchiveException("archive_contains_symlink", "Symbolic links are not allowed: " + entry.getName());
            }
            long size = entry.getSize();  // -1 when the archive doesn't say
            if (size > 0) {
                declaredTotal += size;
                long compressed = entry.getCompressedSize();
                if (size > RATIO_FLOOR_BYTES && compressed > 0 && size / compressed > limits.maxRatio()) {
                    throw new ArchiveException("suspicious_compression_ratio",
                            "An entry expands more than " + limits.maxRatio() + " times: " + entry.getName());
                }
            }
        }
        if (declaredTotal > limits.maxTotalBytes()) {
            throw decompressedTooLarge();
        }
    }

    private ExtractResult write(ZipFile zip, List<ZipArchiveEntry> entries, Path root) throws IOException {
        int written = 0;
        int skipped = 0;
        long total = 0;
        for (ZipArchiveEntry entry : entries) {
            Path dest = root.resolve(entry.getName()).normalize();
            if (!dest.startsWith(root)) {  // second line of defence after the name check
                throw new ArchiveException("unsafe_archive_path", "Unsafe path in archive: " + entry.getName());
            }
            if (entry.isDirectory()) {
                Files.createDirectories(dest);
                continue;
            }
            if (!isSupported(dest) || entry.getSize() > limits.maxFileBytes()) {
                skipped++;  // never decompressed, so a bomb hidden in an image or nested archive does nothing
                continue;
            }
            Files.createDirectories(dest.getParent());
            long copied;
            try (InputStream in = zip.getInputStream(entry);
                 OutputStream out = Files.newOutputStream(dest, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
                copied = copyAtMost(in, out, limits.maxFileBytes());
            } catch (FileAlreadyExistsException duplicate) {
                throw new ArchiveException("invalid_archive", "The archive lists a file twice: " + entry.getName());
            }
            if (copied < 0) {  // the entry was bigger than it claimed
                Files.delete(dest);
                skipped++;
                continue;
            }
            total += copied;
            if (total > limits.maxTotalBytes()) {
                throw decompressedTooLarge();
            }
            written++;
        }
        if (written == 0) {
            throw new ArchiveException("no_supported_files", "The archive contains no supported source files.");
        }
        return new ExtractResult(written, skipped, total);
    }

    /** Copies at most max bytes. Returns the count, or -1 if the input had more. */
    private static long copyAtMost(InputStream in, OutputStream out, long max) throws IOException {
        byte[] buffer = new byte[8192];
        long count = 0;
        int n;
        while ((n = in.read(buffer)) != -1) {
            count += n;
            if (count > max) {
                return -1;
            }
            out.write(buffer, 0, n);
        }
        return count;
    }

    static boolean isUnsafeName(String name) {
        return name.isEmpty()
                || name.indexOf('\0') >= 0
                || name.indexOf('\\') >= 0
                || name.startsWith("/")
                || name.matches("^[A-Za-z]:.*")
                || Arrays.asList(name.split("/")).contains("..");
    }

    private static boolean isSupported(Path file) {
        String name = file.getFileName().toString().toLowerCase(Locale.ROOT);
        int dot = name.lastIndexOf('.');
        return name.equals("dockerfile") || (dot >= 0 && SUPPORTED_EXTENSIONS.contains(name.substring(dot + 1)));
    }

    private ArchiveException decompressedTooLarge() {
        return new ArchiveException("decompressed_too_large",
                "The archive expands to more than " + limits.maxTotalBytes() / (1024 * 1024) + " MB.");
    }
}
