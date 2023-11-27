package com.drkcode.authapp.security;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.util.Optional;
import java.util.stream.Stream;

public class JwtCookieUtil {

    private static final int JWT_COOKIE_MAX_AGE = 7 * 24 * 60 * 60 * 1000;

    private static final String JWT_COOKIE_NAME = "jwt";

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

    public static Optional<Cookie> getCookie(HttpServletRequest request) {
        if (request.getCookies() == null) {
            return Optional.empty();
        }
        return Stream.of(request.getCookies()).filter(cookie -> cookie.getName().equals(JWT_COOKIE_NAME)).findFirst();
    }

}
