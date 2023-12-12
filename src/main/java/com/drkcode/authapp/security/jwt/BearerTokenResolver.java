package com.drkcode.authapp.security.jwt;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpHeaders;

import java.util.Optional;

public abstract class BearerTokenResolver {

    private static final String TOKEN_PREFIX = "Bearer ";

    private BearerTokenResolver() {
    }

    public static Optional<String> getToken(HttpServletRequest request) {
        var bearertoken = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (bearertoken == null || !bearertoken.startsWith(TOKEN_PREFIX)) {
            return Optional.empty();
        }
        var token = bearertoken.replace(TOKEN_PREFIX, "");
        return Optional.of(token);
    }
}
