package dev.sanyam.cg.api;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

/** 401s use the same problem-details shape as every other error, instead of Spring Security's empty body. */
public class ProblemAuthenticationEntryPoint implements AuthenticationEntryPoint {

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException e)
            throws IOException {
        boolean sentToken = request.getHeader(HttpHeaders.AUTHORIZATION) != null;
        String code = sentToken ? "token_invalid" : "not_authenticated";
        String detail = sentToken ? "The access token is invalid or expired. Log in again."
                : "Log in and send the access token in an Authorization: Bearer header.";
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setHeader(HttpHeaders.WWW_AUTHENTICATE, "Bearer");
        response.setContentType("application/problem+json");
        response.getWriter().write("{\"type\":\"https://cg.dev/errors/" + code + "\",\"title\":\"Unauthorized\","
                + "\"status\":401,\"code\":\"" + code + "\",\"detail\":\"" + detail + "\"}");
    }
}
