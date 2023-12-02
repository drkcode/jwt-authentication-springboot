package com.drkcode.authapp.security.impl;

import com.drkcode.authapp.security.JWTAuthenticationProvider;
import com.drkcode.authapp.security.JWTService;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class JWTAuthenticationProviderImpl implements JWTAuthenticationProvider {

    private final UserDetailsService userDetailsService;

    private final PasswordEncoder passwordEncoder;

    private final JWTService jwtService;

    public JWTAuthenticationProviderImpl(UserDetailsService userDetailsService, PasswordEncoder passwordEncoder, JWTService jwtService) {
        this.userDetailsService = userDetailsService;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
    }

    @Override
    public void authenticateWithUsernamePassword(String username, String password) {
        var user = userDetailsService.loadUserByUsername(username);
        var match = passwordEncoder.matches(password, user.getPassword());
        if (!match) throw new BadCredentialsException("Invalid credentials");
        authenticateUser(user);
    }

    @Override
    public void authenticateWithJWT(String jwt) {
        var username = jwtService.verifyToken(jwt);
        var user = userDetailsService.loadUserByUsername(username);
        authenticateUser(user);
    }

    @Override
    public Authentication getAuthentication() {
        return SecurityContextHolder.getContext().getAuthentication();
    }

    private void authenticateUser(UserDetails user) {
        var authToken = new UsernamePasswordAuthenticationToken(user.getUsername(), null, user.getAuthorities());
        SecurityContextHolder.getContext().setAuthentication(authToken);
    }

}
