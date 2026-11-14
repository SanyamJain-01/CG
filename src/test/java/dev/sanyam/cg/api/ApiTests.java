package dev.sanyam.cg.api;

import static org.assertj.core.api.Assertions.assertThat;

import dev.sanyam.cg.TestcontainersConfiguration;
import dev.sanyam.cg.archive.TestZips;
import dev.sanyam.cg.scan.ScanWorker;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;

/** The REST API over real HTTP, against a real Postgres. The worker is driven by hand to keep tests deterministic. */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {"cg.worker.enabled=false", "cg.scanners.enabled=false", "cg.storage-dir=${java.io.tmpdir}/cg-api-test"})
@Import(TestcontainersConfiguration.class)
class ApiTests {

    static final String PASSWORD = "correct-horse-battery";

    @Value("${local.server.port}") int port;
    @Autowired ScanWorker worker;
    @TempDir Path tmp;

    final HttpClient http = HttpClient.newHttpClient();

    @Test
    void registerLoginUploadAndSeeTheResult() throws Exception {
        String token = newUserToken();

        HttpResponse<String> upload = upload(token, "repo.zip", zip(z -> z.file("app.py", "x = 1").file("Main.java", "class Main {}")));
        assertThat(upload.statusCode()).isEqualTo(202);
        assertThat(field(upload.body(), "status")).isEqualTo("QUEUED");
        String id = field(upload.body(), "id");

        worker.processNext();

        HttpResponse<String> scan = send(get("/api/scans/" + id, token));
        assertThat(scan.statusCode()).isEqualTo(200);
        assertThat(field(scan.body(), "status")).isEqualTo("SUCCEEDED");
        assertThat(scan.body()).contains("\"fileCount\":2");

        HttpResponse<String> list = send(get("/api/scans", token));
        assertThat(list.body()).contains(id);

        HttpResponse<String> findings = send(get("/api/scans/" + id + "/findings", token));
        assertThat(findings.statusCode()).isEqualTo(200);
        assertThat(findings.body()).contains("\"total\":0");
        assertThat(upload.headers().firstValue("Location")).hasValue("/api/scans/" + id);
    }

    @Test
    void requestsWithoutAValidTokenGetA401Problem() throws Exception {
        HttpResponse<String> none = send(HttpRequest.newBuilder(url("/api/scans")).GET().build());
        assertThat(none.statusCode()).isEqualTo(401);
        assertThat(none.headers().firstValue("Content-Type")).hasValueSatisfying(t -> assertThat(t).startsWith("application/problem+json"));
        assertThat(field(none.body(), "code")).isEqualTo("not_authenticated");

        HttpResponse<String> forged = send(get("/api/scans", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.forged"));
        assertThat(forged.statusCode()).isEqualTo(401);
        assertThat(field(forged.body(), "code")).isEqualTo("token_invalid");
    }

    @Test
    void usersCannotSeeOrDeleteEachOthersScans() throws Exception {
        String alice = newUserToken();
        String bob = newUserToken();
        String id = field(upload(alice, "repo.zip", zip(z -> z.file("app.py", "x = 1"))).body(), "id");

        assertThat(send(get("/api/scans/" + id, bob)).statusCode()).isEqualTo(404);
        assertThat(send(get("/api/scans/" + id + "/findings", bob)).statusCode()).isEqualTo(404);
        assertThat(send(delete("/api/scans/" + id, bob)).statusCode()).isEqualTo(404);
        assertThat(send(get("/api/scans", bob)).body()).doesNotContain(id);

        assertThat(send(delete("/api/scans/" + id, alice)).statusCode()).isEqualTo(204);
        assertThat(send(get("/api/scans/" + id, alice)).statusCode()).isEqualTo(404);
    }

    @Test
    void registrationIsValidated() throws Exception {
        String email = uniqueEmail();
        assertThat(register(email, PASSWORD).statusCode()).isEqualTo(201);

        HttpResponse<String> duplicate = register(email.toUpperCase(), PASSWORD);
        assertThat(duplicate.statusCode()).isEqualTo(409);
        assertThat(field(duplicate.body(), "code")).isEqualTo("email_taken");

        HttpResponse<String> weak = register(uniqueEmail(), "short");
        assertThat(weak.statusCode()).isEqualTo(422);
        assertThat(field(weak.body(), "code")).isEqualTo("validation_error");
        assertThat(weak.body()).contains("\"field\":\"password\"");
    }

    @Test
    void repeatedWrongPasswordsAreRateLimited() throws Exception {
        String email = uniqueEmail();
        register(email, PASSWORD);
        for (int i = 0; i < 5; i++) {
            assertThat(login(email, "wrong-password-123").statusCode()).isEqualTo(401);
        }

        HttpResponse<String> blocked = login(email, PASSWORD);  // even the right password is refused for now
        assertThat(blocked.statusCode()).isEqualTo(429);
        assertThat(blocked.headers().firstValue("Retry-After")).isPresent();
    }

    @Test
    void uploadErrorsUseStableCodes() throws Exception {
        String token = newUserToken();

        HttpResponse<String> text = upload(token, "notes.txt", "hello".getBytes(StandardCharsets.UTF_8));
        assertThat(text.statusCode()).isEqualTo(415);
        assertThat(field(text.body(), "code")).isEqualTo("not_a_zip");

        HttpResponse<String> unknown = send(get("/api/scans/" + UUID.randomUUID(), token));
        assertThat(field(unknown.body(), "code")).isEqualTo("scan_not_found");

        HttpResponse<String> badId = send(get("/api/scans/not-a-uuid", token));
        assertThat(badId.statusCode()).isEqualTo(400);
        assertThat(field(badId.body(), "code")).isEqualTo("invalid_parameter");
    }

    // ---------- helpers ----------

    interface ZipContent {
        void fill(TestZips zip) throws IOException;
    }

    private byte[] zip(ZipContent content) throws IOException {
        Path file = tmp.resolve(UUID.randomUUID() + ".zip");
        TestZips zip = TestZips.create(file);
        content.fill(zip);
        zip.close();
        return Files.readAllBytes(file);
    }

    private String newUserToken() throws Exception {
        String email = uniqueEmail();
        register(email, PASSWORD);
        return field(login(email, PASSWORD).body(), "accessToken");
    }

    private HttpResponse<String> register(String email, String password) throws Exception {
        return send(json("/api/auth/register", "{\"email\":\"" + email + "\",\"password\":\"" + password + "\"}"));
    }

    private HttpResponse<String> login(String email, String password) throws Exception {
        return send(json("/api/auth/login", "{\"email\":\"" + email + "\",\"password\":\"" + password + "\"}"));
    }

    private HttpResponse<String> upload(String token, String filename, byte[] content) throws Exception {
        String boundary = "cg-" + UUID.randomUUID();
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        body.write(("--" + boundary + "\r\nContent-Disposition: form-data; name=\"file\"; filename=\"" + filename
                + "\"\r\nContent-Type: application/zip\r\n\r\n").getBytes(StandardCharsets.UTF_8));
        body.write(content);
        body.write(("\r\n--" + boundary + "--\r\n").getBytes(StandardCharsets.UTF_8));
        return send(HttpRequest.newBuilder(url("/api/scans"))
                .header("Authorization", "Bearer " + token)
                .header("Content-Type", "multipart/form-data; boundary=" + boundary)
                .POST(HttpRequest.BodyPublishers.ofByteArray(body.toByteArray())).build());
    }

    private HttpRequest json(String path, String body) {
        return HttpRequest.newBuilder(url(path)).header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body)).build();
    }

    private HttpRequest get(String path, String token) {
        return HttpRequest.newBuilder(url(path)).header("Authorization", "Bearer " + token).GET().build();
    }

    private HttpRequest delete(String path, String token) {
        return HttpRequest.newBuilder(url(path)).header("Authorization", "Bearer " + token).DELETE().build();
    }

    private HttpResponse<String> send(HttpRequest request) throws Exception {
        return http.send(request, HttpResponse.BodyHandlers.ofString());
    }

    private URI url(String path) {
        return URI.create("http://localhost:" + port + path);
    }

    private static String uniqueEmail() {
        return "user-" + UUID.randomUUID() + "@example.com";
    }

    /** Reads a string field from a JSON body. Enough for tests; the app itself uses a real JSON library. */
    private static String field(String json, String name) {
        Matcher m = Pattern.compile("\"" + name + "\"\\s*:\\s*\"([^\"]*)\"").matcher(json);
        assertThat(m.find()).as("field %s in %s", name, json).isTrue();
        return m.group(1);
    }
}
