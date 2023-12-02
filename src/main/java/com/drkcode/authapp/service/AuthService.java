package com.drkcode.authapp.service;

import com.drkcode.authapp.dto.SignInRequestDTO;
import com.drkcode.authapp.dto.SignInTokensDTO;
import com.drkcode.authapp.security.JWTAuthenticationProvider;
import com.drkcode.authapp.security.JWTService;
import org.springframework.stereotype.Service;

@Service
public class AuthService {

    private final JWTAuthenticationProvider authenticationProvider;

    private final JWTService jwtService;

    public AuthService(JWTAuthenticationProvider authenticationProvider, JWTService jwtService) {
        this.authenticationProvider = authenticationProvider;
        this.jwtService = jwtService;
    }

    public SignInTokensDTO signIn(SignInRequestDTO request) {
        authenticationProvider.authenticate(request.email(), request.password());
        var authentication = authenticationProvider.getAuthentication();
        var refreshToken = jwtService.getRefreshToken(authentication);
        var accessToken = jwtService.getAccessToken(authentication);
        return new SignInTokensDTO(accessToken, refreshToken);
    }

    public String refresh(String jwt) {
        authenticationProvider.authenticate(jwt);
        var auth = authenticationProvider.getAuthentication();
        return jwtService.getAccessToken(auth);
    }

}
