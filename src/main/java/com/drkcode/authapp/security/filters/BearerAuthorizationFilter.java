package com.drkcode.authapp.security.filters;

import com.drkcode.authapp.security.JWTAuthenticationProvider;
import com.drkcode.authapp.security.jwt.BearerTokenResolver;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class BearerAuthorizationFilter extends OncePerRequestFilter {

    private final JWTAuthenticationProvider authenticationProvider;

    public BearerAuthorizationFilter(JWTAuthenticationProvider authenticationProvider) {
        this.authenticationProvider = authenticationProvider;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        var token = BearerTokenResolver.getToken(request);
        token.ifPresent(authenticationProvider::authenticate);
        filterChain.doFilter(request, response);
    }
}
