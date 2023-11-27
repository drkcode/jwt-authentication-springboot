package com.drkcode.authapp.service;

import com.drkcode.authapp.dto.SignInRequestDTO;
import com.drkcode.authapp.dto.SignInTokensDTO;
import com.drkcode.authapp.security.JWTService;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class AuthService {

    private final JWTService jwtService;
    private final UserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;

    public AuthService(JWTService jwtService, UserDetailsService userDetailsService, PasswordEncoder passwordEncoder) {
        this.jwtService = jwtService;
        this.userDetailsService = userDetailsService;
        this.passwordEncoder = passwordEncoder;
    }

    public SignInTokensDTO signIn(SignInRequestDTO request) {
        var user = userDetailsService.loadUserByUsername(request.email());
        var match = passwordEncoder.matches(request.password(), user.getPassword());
        if (!match) throw new BadCredentialsException(request.password());
        authenticateUser(user);
        return new SignInTokensDTO(jwtService.getAccessToken(user), jwtService.getRefreshToken(user));
    }

    public String refresh(String refreshToken) {
        var userInfo = jwtService.verifyRefreshToken(refreshToken);
        var user = userDetailsService.loadUserByUsername(userInfo.getUsername());
        authenticateUser(user);
        return jwtService.getAccessToken(user);
    }

    private void authenticateUser(UserDetails user) {
        var authToken = new UsernamePasswordAuthenticationToken(user.getUsername(), null, user.getAuthorities());
        SecurityContextHolder.getContext().setAuthentication(authToken);
    }
}
