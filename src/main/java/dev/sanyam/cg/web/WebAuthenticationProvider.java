package dev.sanyam.cg.web;

import dev.sanyam.cg.api.ApiException;
import dev.sanyam.cg.user.AuthService;
import dev.sanyam.cg.user.User;
import java.util.List;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

/** Dashboard login goes through AuthService, so it shares the API's password check and rate limit. */
@Component
class WebAuthenticationProvider implements AuthenticationProvider {

    private final AuthService auth;

    WebAuthenticationProvider(AuthService auth) {
        this.auth = auth;
    }

    @Override
    public Authentication authenticate(Authentication login) {
        try {
            User user = auth.authenticate(login.getName(), String.valueOf(login.getCredentials()));
            // the principal is the user id, the same value the API puts in a token's subject
            return UsernamePasswordAuthenticationToken.authenticated(user.getId().toString(), null,
                    List.of(new SimpleGrantedAuthority("ROLE_USER")));
        } catch (ApiException e) {
            if (e.getStatus() == HttpStatus.TOO_MANY_REQUESTS) {
                throw new LockedException(e.getMessage());
            }
            throw new BadCredentialsException("Email or password is wrong.");
        }
    }

    @Override
    public boolean supports(Class<?> type) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(type);
    }
}
