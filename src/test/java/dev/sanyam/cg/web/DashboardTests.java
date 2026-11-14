package dev.sanyam.cg.web;

import static org.assertj.core.api.Assertions.assertThat;

import dev.sanyam.cg.TestcontainersConfiguration;
import dev.sanyam.cg.archive.TestZips;
import dev.sanyam.cg.scan.ScanWorker;
import java.io.ByteArrayOutputStream;
import java.net.CookieManager;
import java.net.CookiePolicy;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;

/** The dashboard as a browser sees it: session cookies, CSRF tokens, redirects. */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {"cg.worker.enabled=false", "cg.scanners.enabled=false", "cg.storage-dir=${java.io.tmpdir}/cg-web-test"})
@Import(TestcontainersConfiguration.class)
class DashboardTests {

    static final String PASSWORD = "correct-horse-battery";

    @Value("${local.server.port}") int port;
    @Autowired ScanWorker worker;
    @TempDir Path tmp;

    @Test
    void registerLogInUploadAndSeeTheScan() throws Exception {
        Browser browser = new Browser();
        browser.signUpAndLogIn();

        HttpResponse<String> upload = browser.upload("repo.zip", zip());
        assertThat(upload.statusCode()).isEqualTo(302);
        String location = upload.headers().firstValue("Location").orElseThrow();
        assertThat(location).contains("/scans/");

        while (worker.processNext()) { }  // drain the queue: earlier tests may have left scans in it

        HttpResponse<String> page = browser.get(location.substring(location.indexOf("/scans/")));
        assertThat(page.statusCode()).isEqualTo(200);
        assertThat(page.body()).contains("repo.zip").contains("SUCCEEDED").contains("No issues found");
        assertThat(browser.get("/").body()).contains("repo.zip");
    }

    @Test
    void pagesNeedALogin() throws Exception {
        HttpResponse<String> home = new Browser().get("/");
        assertThat(home.statusCode()).isEqualTo(302);
        assertThat(home.headers().firstValue("Location")).hasValueSatisfying(l -> assertThat(l).contains("/login"));
    }

    @Test
    void formsWithoutACsrfTokenAreRejected() throws Exception {
        Browser browser = new Browser();
        browser.get("/login");  // gets a session, but the token is left out below

        HttpResponse<String> login = browser.post("/login", Map.of("username", "x@example.com", "password", PASSWORD), false);

        assertThat(login.statusCode()).isEqualTo(403);
    }

    @Test
    void pagesSendAStrictContentSecurityPolicy() throws Exception {
        HttpResponse<String> login = new Browser().get("/login");
        assertThat(login.headers().firstValue("Content-Security-Policy"))
                .hasValueSatisfying(csp -> assertThat(csp).contains("default-src 'self'").contains("frame-ancestors 'none'"));
    }

    @Test
    void usersCannotOpenEachOthersScans() throws Exception {
        Browser alice = new Browser();
        alice.signUpAndLogIn();
        String location = alice.upload("repo.zip", zip()).headers().firstValue("Location").orElseThrow();
        String path = location.substring(location.indexOf("/scans/"));

        Browser bob = new Browser();
        bob.signUpAndLogIn();
        HttpResponse<String> page = bob.get(path);

        assertThat(page.statusCode()).isEqualTo(404);
        assertThat(page.body()).contains("Not found").doesNotContain("repo.zip");
    }

    @Test
    void webLoginSharesTheWrongPasswordLimit() throws Exception {
        Browser browser = new Browser();
        String email = browser.signUp();
        for (int i = 0; i < 5; i++) {
            assertThat(browser.logIn(email, "wrong-password-123").headers().firstValue("Location"))
                    .hasValueSatisfying(l -> assertThat(l).contains("/login?error"));
        }
        assertThat(browser.logIn(email, PASSWORD).headers().firstValue("Location"))
                .hasValueSatisfying(l -> assertThat(l).contains("/login?locked"));
    }

    private byte[] zip() throws Exception {
        Path file = tmp.resolve(UUID.randomUUID() + ".zip");
        TestZips zip = TestZips.create(file).file("app.py", "x = 1");
        zip.close();
        return Files.readAllBytes(file);
    }

    /** A tiny browser: keeps cookies, doesn't follow redirects, sends the page's CSRF token with forms. */
    class Browser {

        final HttpClient http = HttpClient.newBuilder()
                .cookieHandler(new CookieManager(null, CookiePolicy.ACCEPT_ALL))
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
        String csrf = "";

        HttpResponse<String> get(String path) throws Exception {
            HttpResponse<String> r = http.send(HttpRequest.newBuilder(url(path)).GET().build(),
                    HttpResponse.BodyHandlers.ofString());
            Matcher m = Pattern.compile("name=\"_csrf\"\\s+value=\"([^\"]+)\"").matcher(r.body());
            if (m.find()) {
                csrf = m.group(1);
            }
            return r;
        }

        HttpResponse<String> post(String path, Map<String, String> fields, boolean withCsrf) throws Exception {
            Map<String, String> all = new LinkedHashMap<>(fields);
            if (withCsrf) {
                all.put("_csrf", csrf);
            }
            String body = all.entrySet().stream()
                    .map(e -> e.getKey() + "=" + URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8))
                    .collect(Collectors.joining("&"));
            return http.send(HttpRequest.newBuilder(url(path))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .POST(HttpRequest.BodyPublishers.ofString(body)).build(), HttpResponse.BodyHandlers.ofString());
        }

        String signUp() throws Exception {
            String email = "web-" + UUID.randomUUID() + "@example.com";
            get("/register");
            HttpResponse<String> r = post("/register", Map.of("email", email, "password", PASSWORD), true);
            assertThat(r.headers().firstValue("Location")).hasValueSatisfying(l -> assertThat(l).contains("/login?registered"));
            return email;
        }

        HttpResponse<String> logIn(String email, String password) throws Exception {
            get("/login");
            return post("/login", Map.of("username", email, "password", password), true);
        }

        void signUpAndLogIn() throws Exception {
            HttpResponse<String> r = logIn(signUp(), PASSWORD);
            assertThat(r.statusCode()).isEqualTo(302);
            assertThat(r.headers().firstValue("Location")).hasValueSatisfying(l -> assertThat(l).doesNotContain("login"));
        }

        HttpResponse<String> upload(String filename, byte[] content) throws Exception {
            get("/");  // fresh CSRF token for this session
            String boundary = "cg-" + UUID.randomUUID();
            ByteArrayOutputStream body = new ByteArrayOutputStream();
            body.write(("--" + boundary + "\r\nContent-Disposition: form-data; name=\"_csrf\"\r\n\r\n" + csrf + "\r\n")
                    .getBytes(StandardCharsets.UTF_8));
            body.write(("--" + boundary + "\r\nContent-Disposition: form-data; name=\"file\"; filename=\"" + filename
                    + "\"\r\nContent-Type: application/zip\r\n\r\n").getBytes(StandardCharsets.UTF_8));
            body.write(content);
            body.write(("\r\n--" + boundary + "--\r\n").getBytes(StandardCharsets.UTF_8));
            return http.send(HttpRequest.newBuilder(url("/scans"))
                    .header("Content-Type", "multipart/form-data; boundary=" + boundary)
                    .POST(HttpRequest.BodyPublishers.ofByteArray(body.toByteArray())).build(),
                    HttpResponse.BodyHandlers.ofString());
        }

        private URI url(String path) {
            return URI.create("http://localhost:" + port + path);
        }
    }
}
