package com.drkcode.authapp.security;

import org.springframework.security.core.Authentication;

public interface JWTService {
    String getAccessToken(Authentication authentication);

    String getRefreshToken(Authentication authentication);

    String verifyToken(String token);
}
