package com.drkcode.authapp.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class BearerAuthorizationFilter extends OncePerRequestFilter {

    private final JWTService jwtService;

    public BearerAuthorizationFilter(JWTService jwtService) {
        this.jwtService = jwtService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        var token = BearerTokenUtil.getToken(request);
        if (token.isPresent()) {
            var userInfo = jwtService.verifyAccessToken(token.get());
            var userRoles = userInfo.getRoles().stream().map(SimpleGrantedAuthority::new).toList();
            var userAuthentication = new UsernamePasswordAuthenticationToken(userInfo.getUsername(), null, userRoles);
            SecurityContextHolder.getContext().setAuthentication(userAuthentication);
        }
        filterChain.doFilter(request, response);
    }


}
