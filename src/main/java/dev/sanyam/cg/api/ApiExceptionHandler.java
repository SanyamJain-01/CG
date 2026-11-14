package dev.sanyam.cg.api;

import dev.sanyam.cg.archive.ArchiveException;
import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.ErrorResponse;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;
import org.springframework.web.multipart.MaxUploadSizeExceededException;
import org.springframework.web.multipart.support.MissingServletRequestPartException;

/** Every error leaves the API in one shape: RFC 9457 problem details plus a stable "code". Never a stack trace. */
@RestControllerAdvice
class ApiExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(ApiExceptionHandler.class);

    @ExceptionHandler(ApiException.class)
    ResponseEntity<ProblemDetail> api(ApiException e) {
        ResponseEntity.BodyBuilder response = ResponseEntity.status(e.getStatus());
        if (e.getRetryAfterSeconds() > 0) {
            response.header(HttpHeaders.RETRY_AFTER, String.valueOf(e.getRetryAfterSeconds()));
        }
        return response.body(problem(e.getStatus(), e.getCode(), e.getMessage()));
    }

    @ExceptionHandler(ArchiveException.class)
    ResponseEntity<ProblemDetail> archive(ArchiveException e) {
        HttpStatus status = switch (e.getCode()) {
            case "archive_too_large" -> HttpStatus.CONTENT_TOO_LARGE;
            case "not_a_zip" -> HttpStatus.UNSUPPORTED_MEDIA_TYPE;
            default -> HttpStatus.BAD_REQUEST;
        };
        return ResponseEntity.status(status).body(problem(status, e.getCode(), e.getMessage()));
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    ResponseEntity<ProblemDetail> invalidBody(MethodArgumentNotValidException e) {
        HttpStatus status = HttpStatus.UNPROCESSABLE_CONTENT;
        ProblemDetail body = problem(status, "validation_error", "Some fields are invalid.");
        List<Map<String, String>> errors = e.getBindingResult().getFieldErrors().stream()
                .map(f -> Map.of("field", f.getField(), "message", String.valueOf(f.getDefaultMessage())))
                .toList();
        body.setProperty("errors", errors);
        return ResponseEntity.status(status).body(body);
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    ResponseEntity<ProblemDetail> unreadable(HttpMessageNotReadableException e) {
        return simple(HttpStatus.BAD_REQUEST, "malformed_request", "The request body is not valid JSON.");
    }

    @ExceptionHandler(MissingServletRequestPartException.class)
    ResponseEntity<ProblemDetail> missingFile(MissingServletRequestPartException e) {
        return simple(HttpStatus.BAD_REQUEST, "missing_file", "Send the ZIP as a multipart field named \"file\".");
    }

    @ExceptionHandler(MaxUploadSizeExceededException.class)
    ResponseEntity<ProblemDetail> tooLarge(MaxUploadSizeExceededException e) {
        return simple(HttpStatus.CONTENT_TOO_LARGE, "archive_too_large", "Uploads are limited to 20 MB.");
    }

    @ExceptionHandler(MethodArgumentTypeMismatchException.class)
    ResponseEntity<ProblemDetail> badParameter(MethodArgumentTypeMismatchException e) {
        return simple(HttpStatus.BAD_REQUEST, "invalid_parameter", "Invalid value for \"" + e.getName() + "\".");
    }

    /** Spring's own errors (unknown URL, wrong method, wrong content type) keep their status; anything else is a 500. */
    @ExceptionHandler(Exception.class)
    ResponseEntity<ProblemDetail> other(Exception e) {
        if (e instanceof ErrorResponse spring) {
            HttpStatusCode status = spring.getStatusCode();
            String code = switch (status.value()) {
                case 404 -> "not_found";
                case 405 -> "method_not_allowed";
                case 406 -> "not_acceptable";
                case 415 -> "unsupported_media_type";
                default -> "bad_request";
            };
            return ResponseEntity.status(status).body(problem(status, code, spring.getBody().getDetail()));
        }
        String traceId = UUID.randomUUID().toString();
        log.error("Unhandled error trace_id={}", traceId, e);
        ProblemDetail body = problem(HttpStatus.INTERNAL_SERVER_ERROR, "internal_error", "Something went wrong on our side.");
        body.setProperty("trace_id", traceId);  // lets support find the log line without exposing details
        return ResponseEntity.internalServerError().body(body);
    }

    private static ResponseEntity<ProblemDetail> simple(HttpStatus status, String code, String detail) {
        return ResponseEntity.status(status).body(problem(status, code, detail));
    }

    static ProblemDetail problem(HttpStatusCode status, String code, String detail) {
        ProblemDetail body = ProblemDetail.forStatusAndDetail(status, detail);
        body.setType(URI.create("https://cg.dev/errors/" + code));
        body.setProperty("code", code);
        return body;
    }
}
