package com.drkcode.authapp.security;

import org.springframework.security.core.userdetails.UserDetails;

public interface JWTService {
    String getAccessToken(UserDetails user);

    String getRefreshToken(UserDetails user);

    AccessTokenUserInfo verifyAccessToken(String token);

    RefreshTokenUserInfo verifyRefreshToken(String token);
}
