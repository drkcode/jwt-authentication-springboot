package com.drkcode.authapp.security.impl;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.drkcode.authapp.security.JWTService;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

@Component
public class JWTServiceImpl implements JWTService {

    private JWTCreator.Builder jwtBuilder;
    private Algorithm JWT_ALGORITM;
    private JWTVerifier jwtVerifier;
    @Value("${jwt.secret}")
    private String SECRET;

    @PostConstruct
    private void init() {
        JWT_ALGORITM = Algorithm.HMAC512(SECRET.getBytes(StandardCharsets.UTF_8));
        jwtBuilder = JWT.create();
        jwtVerifier = JWT.require(JWT_ALGORITM).build();
    }

    @Override
    public String getAccessToken(Authentication authentication) {
        return jwtBuilder
                .withSubject(authentication.getPrincipal().toString())
                .withClaim("roles", authentication.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList())
                .withExpiresAt(Instant.now().plus(15, ChronoUnit.MINUTES))
                .sign(JWT_ALGORITM);
    }

    @Override
    public String getRefreshToken(Authentication authentication) {
        return jwtBuilder
                .withSubject(authentication.getPrincipal().toString())
                .withExpiresAt(Instant.now().plus(7, ChronoUnit.DAYS))
                .sign(JWT_ALGORITM);
    }

    @Override
    public String verifyToken(String token) {
        var decodedJWT = jwtVerifier.verify(token);
        return decodedJWT.getSubject();
    }
}
