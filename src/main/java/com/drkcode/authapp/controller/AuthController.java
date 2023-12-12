package com.drkcode.authapp.controller;

import com.drkcode.authapp.dto.AccessTokenResponseDTO;
import com.drkcode.authapp.dto.SignInRequestDTO;
import com.drkcode.authapp.security.jwt.JWTCookieUtil;
import com.drkcode.authapp.service.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @GetMapping("/refresh")
    public ResponseEntity<?> refresh(HttpServletRequest request) {
        var jwtCookie = JWTCookieUtil.getCookie(request);
        var accessToken = authService.refresh(jwtCookie.getValue());
        return ResponseEntity.ok(new AccessTokenResponseDTO(accessToken));
    }

    @PostMapping("/sign-in")
    public ResponseEntity<AccessTokenResponseDTO> signIn(@RequestBody SignInRequestDTO request, HttpServletResponse response) {
        var tokens = authService.signIn(request);
        var jwtCookie = JWTCookieUtil.createCookie(tokens.refreshToken());
        response.addCookie(jwtCookie);
        return ResponseEntity.ok(new AccessTokenResponseDTO(tokens.accessToken()));
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletResponse response) {
        JWTCookieUtil.removeCookie(response);
        return ResponseEntity.noContent().build();
    }
}
