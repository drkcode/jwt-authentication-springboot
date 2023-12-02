package com.drkcode.authapp.security;

import org.springframework.security.core.Authentication;

public interface JWTAuthenticationProvider {
    void authenticateWithUsernamePassword(String username, String password);

    void authenticateWithJWT(String jwt);

    Authentication getAuthentication();
}
