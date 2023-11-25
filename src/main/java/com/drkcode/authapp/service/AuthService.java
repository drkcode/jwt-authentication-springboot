package com.drkcode.authapp.service;

import com.drkcode.authapp.dto.SignInRequestDTO;
import com.drkcode.authapp.dto.SignInTokens;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class AuthService {

    private JWTTokenService tokenService;
    private UserDetailsService userDetailsService;
    private PasswordEncoder passwordEncoder;

    public AuthService(JWTTokenService tokenService, UserDetailsService userDetailsService, PasswordEncoder passwordEncoder) {
        this.tokenService = tokenService;
        this.userDetailsService = userDetailsService;
        this.passwordEncoder = passwordEncoder;
    }

    public SignInTokens signIn(SignInRequestDTO request) {
        var user = userDetailsService.loadUserByUsername(request.email());
        var match = passwordEncoder.matches(request.password(), user.getPassword());
        if (!match) throw new BadCredentialsException(request.password());
        authenticateUser(user);
        return new SignInTokens(tokenService.getAccessToken(user), tokenService.getRefreshToken(user));
    }

    public String refresh(String refreshToken) {
        var userInfo = tokenService.verifyRefreshToken(refreshToken);
        var user = userDetailsService.loadUserByUsername(userInfo.getUsername());
        authenticateUser(user);
        return tokenService.getAccessToken(user);
    }

    private void authenticateUser(UserDetails user) {
        var authToken = new UsernamePasswordAuthenticationToken(user.getUsername(), null, user.getAuthorities());
        SecurityContextHolder.getContext().setAuthentication(authToken);
    }

}
