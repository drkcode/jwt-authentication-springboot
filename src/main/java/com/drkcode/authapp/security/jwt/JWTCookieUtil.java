package com.drkcode.authapp.security.jwt;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.BadCredentialsException;

import java.util.stream.Stream;

public abstract class JWTCookieUtil {

    private static final int JWT_COOKIE_MAX_AGE = 7 * 24 * 60 * 60 * 1000;

    private static final String JWT_COOKIE_NAME = "jwt";

    private JWTCookieUtil() {
    }

    public static Cookie createCookie(String tokenValue) {
        var cookie = new Cookie(JWT_COOKIE_NAME, tokenValue);
        cookie.setMaxAge(JWT_COOKIE_MAX_AGE);
        cookie.setHttpOnly(true);
        cookie.setAttribute("SameSite", "None");
        cookie.setPath("/");
        cookie.setSecure(true);
        return cookie;
    }

    public static void removeCookie(HttpServletResponse response) {
        var cookie = new Cookie(JWT_COOKIE_NAME, "");
        cookie.setMaxAge(0);
        cookie.setPath("/");
        response.addCookie(cookie);
    }

    public static Cookie getCookie(HttpServletRequest request) {
        if (request.getCookies() != null) {
            var jwtCookie = Stream.of(request.getCookies()).filter(cookie -> cookie.getName().equals(JWT_COOKIE_NAME)).findFirst();
            if (jwtCookie.isPresent()) {
                return jwtCookie.get();
            }
        }
        throw new BadCredentialsException("Invalid jwt cookie.");
    }

}
