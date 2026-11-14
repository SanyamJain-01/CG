package dev.sanyam.cg.archive;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import org.apache.commons.compress.archivers.zip.ZipArchiveEntry;
import org.apache.commons.compress.archivers.zip.ZipArchiveOutputStream;

/** Builds the malicious and normal ZIPs the tests use. Nothing here is checked into the repo as a binary. */
public final class TestZips {

    private final ZipArchiveOutputStream out;

    private TestZips(Path file) throws IOException {
        out = new ZipArchiveOutputStream(file);
    }

    public static TestZips create(Path file) throws IOException {
        return new TestZips(file);
    }

    public TestZips file(String name, String content) throws IOException {
        return file(name, content.getBytes(StandardCharsets.UTF_8));
    }

    public TestZips file(String name, byte[] content) throws IOException {
        out.putArchiveEntry(new ZipArchiveEntry(name));
        out.write(content);
        out.closeArchiveEntry();
        return this;
    }

    public TestZips symlink(String name, String target) throws IOException {
        ZipArchiveEntry entry = new ZipArchiveEntry(name);
        entry.setUnixMode(0120777);  // file type "symbolic link" in the Unix mode bits
        out.putArchiveEntry(entry);
        out.write(target.getBytes(StandardCharsets.UTF_8));
        out.closeArchiveEntry();
        return this;
    }

    public void close() throws IOException {
        out.close();
    }

    public static void writeGarbage(Path file) throws IOException {
        try (OutputStream o = Files.newOutputStream(file)) {
            o.write("PK\u0003\u0004 this is not really a zip".getBytes(StandardCharsets.UTF_8));
        }
    }
}
