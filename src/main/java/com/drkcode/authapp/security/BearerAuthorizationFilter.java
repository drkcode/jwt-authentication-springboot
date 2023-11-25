package com.drkcode.authapp.security;

import com.drkcode.authapp.service.JWTTokenService;
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

    private final JWTTokenService tokenService;

    public BearerAuthorizationFilter(JWTTokenService tokenService) {
        this.tokenService = tokenService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        var token = BearerTokenUtil.getToken(request);
        if (token.isPresent()) {
            var userInfo = tokenService.verifyAccessToken(token.get());
            var userRoles = userInfo.getRoles().stream().map(SimpleGrantedAuthority::new).toList();
            var userAuthentication = new UsernamePasswordAuthenticationToken(userInfo.getUsername(), null, userRoles);
            SecurityContextHolder.getContext().setAuthentication(userAuthentication);
        }
        filterChain.doFilter(request, response);
    }


}
