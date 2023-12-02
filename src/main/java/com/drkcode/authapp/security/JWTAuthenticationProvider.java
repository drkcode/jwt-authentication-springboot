package com.drkcode.authapp.security;

import org.springframework.security.core.Authentication;

public interface JWTAuthenticationProvider {
    void authenticate(String username, String password);

    void authenticate(String jwt);

    Authentication getAuthentication();
}
