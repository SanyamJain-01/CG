package dev.sanyam.cg.user;

import dev.sanyam.cg.api.ApiException;
import dev.sanyam.cg.security.RateLimiter;
import dev.sanyam.cg.security.TokenService;
import java.time.Duration;
import java.util.Locale;
import java.util.Optional;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class AuthService {

    static final int MAX_FAILED_LOGINS = 5;
    static final Duration LOGIN_WINDOW = Duration.ofMinutes(15);

    private final UserRepository users;
    private final PasswordEncoder encoder;
    private final TokenService tokens;
    private final RateLimiter limiter;
    private final String dummyHash;

    public AuthService(UserRepository users, PasswordEncoder encoder, TokenService tokens, RateLimiter limiter) {
        this.users = users;
        this.encoder = encoder;
        this.tokens = tokens;
        this.limiter = limiter;
        this.dummyHash = encoder.encode("not-a-real-password");
    }

    public User register(String email, String password) {
        String normalized = normalize(email);
        if (users.findByEmail(normalized).isPresent()) {
            throw emailTaken();
        }
        try {
            return users.saveAndFlush(new User(normalized, encoder.encode(password)));
        } catch (DataIntegrityViolationException race) {  // two sign-ups with the same email at once
            throw emailTaken();
        }
    }

    /** Issues an API token after checking the password. */
    public String login(String email, String password) {
        return tokens.issue(authenticate(email, password));
    }

    /** Checks email and password, with the wrong-password rate limit. Used by the API and the dashboard. */
    public User authenticate(String email, String password) {
        String normalized = normalize(email);
        String key = "login:" + normalized;
        long wait = limiter.retryAfter(key, MAX_FAILED_LOGINS, LOGIN_WINDOW);
        if (wait > 0) {
            throw ApiException.rateLimited(wait);
        }
        Optional<User> user = users.findByEmail(normalized);
        // hash even when the user doesn't exist, so response time doesn't reveal which emails are registered
        boolean ok = encoder.matches(password, user.map(User::getPasswordHash).orElse(dummyHash)) && user.isPresent();
        if (!ok) {
            limiter.record(key, LOGIN_WINDOW);
            throw new ApiException(HttpStatus.UNAUTHORIZED, "invalid_credentials", "Email or password is wrong.");
        }
        limiter.reset(key);
        return user.get();
    }

    /** Emails are stored lower-case, so lookups never depend on how the user typed them. */
    static String normalize(String email) {
        return email.strip().toLowerCase(Locale.ROOT);
    }

    private static ApiException emailTaken() {
        return new ApiException(HttpStatus.CONFLICT, "email_taken", "An account with this email already exists.");
    }
}
