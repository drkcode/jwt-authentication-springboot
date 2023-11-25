package com.drkcode.authapp.controller;

import com.drkcode.authapp.dto.AccessTokenResponseDto;
import com.drkcode.authapp.dto.SignInRequestDTO;
import com.drkcode.authapp.security.JwtCookieUtil;
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
        var jwtCookie = JwtCookieUtil.getCookie(request);
        if (jwtCookie.isEmpty()) return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        var refreshToken = jwtCookie.get().getValue();
        var accessToken = authService.refresh(refreshToken);
        return ResponseEntity.ok(new AccessTokenResponseDto(accessToken));
    }

    @PostMapping("/sign-in")
    public ResponseEntity<AccessTokenResponseDto> signIn(@RequestBody SignInRequestDTO request, HttpServletResponse response) {
        var authTokens = authService.signIn(request);
        var jwtCookie = JwtCookieUtil.createCookie(authTokens.refreshToken());
        response.addCookie(jwtCookie);
        return ResponseEntity.ok(new AccessTokenResponseDto(authTokens.accessToken()));
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletResponse response) {
        JwtCookieUtil.removeCookie(response);
        return ResponseEntity.noContent().build();
    }
}
