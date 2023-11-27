package com.drkcode.authapp.security;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpHeaders;

import java.util.Optional;

public class BearerTokenUtil {

    public static final String TOKEN_PREFIX = "Bearer ";

    public static Optional<String> getToken(HttpServletRequest request) {
        var bearertoken = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (bearertoken == null || !bearertoken.startsWith(TOKEN_PREFIX)) {
            return Optional.empty();
        }
        var token = bearertoken.replace(TOKEN_PREFIX, "");
        return Optional.of(token);
    }
}
