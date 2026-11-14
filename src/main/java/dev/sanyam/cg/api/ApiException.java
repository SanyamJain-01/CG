package dev.sanyam.cg.api;

import org.springframework.http.HttpStatus;

/** An expected error with a stable code, turned into an RFC 9457 problem response by ApiExceptionHandler. */
public class ApiException extends RuntimeException {

    private final HttpStatus status;
    private final String code;
    private final long retryAfterSeconds;

    public ApiException(HttpStatus status, String code, String message) {
        this(status, code, message, 0);
    }

    private ApiException(HttpStatus status, String code, String message, long retryAfterSeconds) {
        super(message);
        this.status = status;
        this.code = code;
        this.retryAfterSeconds = retryAfterSeconds;
    }

    public static ApiException rateLimited(long retryAfterSeconds) {
        return new ApiException(HttpStatus.TOO_MANY_REQUESTS, "rate_limited",
                "Too many requests. Try again in " + retryAfterSeconds + " seconds.", retryAfterSeconds);
    }

    public static ApiException scanNotFound() {
        return new ApiException(HttpStatus.NOT_FOUND, "scan_not_found", "No scan with that id.");
    }

    public HttpStatus getStatus() { return status; }
    public String getCode() { return code; }
    public long getRetryAfterSeconds() { return retryAfterSeconds; }
}
