package com.drkcode.authapp.controller;

import com.drkcode.authapp.dto.AccessTokenResponseDTO;
import com.drkcode.authapp.dto.SignInRequestDTO;
import com.drkcode.authapp.security.JWTCookieUtil;
import com.drkcode.authapp.service.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @GetMapping("/refresh")
    public ResponseEntity<?> refresh(HttpServletRequest request) {
        var jwtCookie = JWTCookieUtil.getCookie(request);
        if (jwtCookie.isEmpty()) return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        var refreshToken = jwtCookie.get().getValue();
        var accessToken = authService.refresh(refreshToken);
        return ResponseEntity.ok(new AccessTokenResponseDTO(accessToken));
    }

    @PostMapping("/sign-in")
    public ResponseEntity<AccessTokenResponseDTO> signIn(@RequestBody SignInRequestDTO request, HttpServletResponse response) {
        var authTokens = authService.signIn(request);
        var jwtCookie = JWTCookieUtil.createCookie(authTokens.refreshToken());
        response.addCookie(jwtCookie);
        return ResponseEntity.ok(new AccessTokenResponseDTO(authTokens.accessToken()));
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletResponse response) {
        JWTCookieUtil.removeCookie(response);
        return ResponseEntity.noContent().build();
    }
}
