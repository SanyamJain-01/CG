package dev.sanyam.cg.archive;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class SafeExtractorTests {

    @TempDir Path tmp;
    Path zip;
    Path out;
    SafeExtractor extractor = new SafeExtractor(ArchiveLimits.DEFAULT);

    @BeforeEach
    void setUp() throws IOException {
        zip = tmp.resolve("upload.zip");
        out = Files.createDirectory(tmp.resolve("out"));
    }

    @Test
    void extractsSourceFilesAndSkipsEverythingElse() throws IOException {
        TestZips.create(zip).file("app.py", "print(1)").file("src/Main.java", "class Main {}")
                .file("logo.png", new byte[] {1, 2, 3}).file("vendor/lib.zip", new byte[] {4}).close();

        ExtractResult result = extractor.extract(zip, out);

        assertThat(result.filesWritten()).isEqualTo(2);
        assertThat(result.filesSkipped()).isEqualTo(2);
        assertThat(out.resolve("src/Main.java")).hasContent("class Main {}");
        assertThat(out.resolve("logo.png")).doesNotExist();
    }

    @ParameterizedTest
    @ValueSource(strings = {"../evil.py", "a/../../evil.py", "/etc/evil.py", "..\\evil.py", "C:/evil.py"})
    void rejectsPathsThatEscapeTheFolder(String name) throws IOException {
        TestZips.create(zip).file("ok.py", "x = 1").file(name, "pwned").close();

        assertCode("unsafe_archive_path");
        assertThat(tmp.resolve("evil.py")).doesNotExist();
        assertThat(out.resolve("ok.py")).doesNotExist();  // nothing is written when any entry is bad
    }

    @Test
    void rejectsSymlinks() throws IOException {
        TestZips.create(zip).file("ok.py", "x = 1").symlink("secrets.py", "/proc/self/environ").close();
        assertCode("archive_contains_symlink");
    }

    @Test
    void rejectsTooManyEntries() throws IOException {
        extractor = new SafeExtractor(new ArchiveLimits(3, 1_000_000, 1_000_000, 100));
        TestZips.create(zip).file("a.py", "1").file("b.py", "2").file("c.py", "3").file("d.py", "4").close();
        assertCode("too_many_files");
    }

    @Test
    void rejectsZipBombs() throws IOException {
        TestZips.create(zip).file("bomb.py", new byte[10 * 1024 * 1024]).close();  // 10 MB of zeros, ~10 KB zipped
        assertCode("suspicious_compression_ratio");
    }

    @Test
    void rejectsArchivesThatExpandTooFar() throws IOException {
        extractor = new SafeExtractor(new ArchiveLimits(100, 1_000, 1_000_000, 100));
        TestZips.create(zip).file("a.py", "x".repeat(600)).file("b.py", "y".repeat(600)).close();
        assertCode("decompressed_too_large");
    }

    @Test
    void rejectsDamagedArchives() throws IOException {
        TestZips.writeGarbage(zip);
        assertCode("invalid_archive");
    }

    @Test
    void rejectsArchivesWithNoSourceCode() throws IOException {
        TestZips.create(zip).file("photo.png", new byte[] {1}).close();
        assertCode("no_supported_files");
    }

    private void assertCode(String code) {
        assertThatThrownBy(() -> extractor.extract(zip, out))
                .isInstanceOf(ArchiveException.class)
                .hasFieldOrPropertyWithValue("code", code);
    }
}
