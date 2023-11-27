package com.drkcode.authapp.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

@Component
public class JWTServiceImpl implements JWTService {

    private static final Algorithm JWT_ALGORITM = Algorithm.HMAC512("secret-key".getBytes(StandardCharsets.UTF_8));
    private final JWTCreator.Builder jwtBuilder = JWT.create();
    private final JWTVerifier jwtVerifier = JWT.require(JWT_ALGORITM).build();

    public String getAccessToken(UserDetails user) {
        return jwtBuilder
                .withSubject(AccessTokenUserInfo.toJson(user))
                .withExpiresAt(Instant.now().plus(15, ChronoUnit.MINUTES))
                .sign(JWT_ALGORITM);
    }

    public String getRefreshToken(UserDetails user) {
        return jwtBuilder
                .withSubject(RefreshTokenUserInfo.toJson(user))
                .withExpiresAt(Instant.now().plus(7, ChronoUnit.DAYS))
                .sign(JWT_ALGORITM);
    }

    public AccessTokenUserInfo verifyAccessToken(String token) {
        var decodedJWT = jwtVerifier.verify(token);
        return AccessTokenUserInfo.fromJson(decodedJWT.getSubject());
    }

    public RefreshTokenUserInfo verifyRefreshToken(String token) {
        var decodedJWT = jwtVerifier.verify(token);
        return RefreshTokenUserInfo.fromJson(decodedJWT.getSubject());
    }
}