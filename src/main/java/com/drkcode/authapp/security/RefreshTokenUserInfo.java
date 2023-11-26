package com.drkcode.authapp.security;

import com.google.gson.Gson;
import org.springframework.security.core.userdetails.UserDetails;

public class RefreshTokenUserInfo {

    private static final Gson gson = new Gson();
    private final String username;

    private RefreshTokenUserInfo(String username) {
        this.username = username;
    }

    public static String toJson(UserDetails user) {
        var userInfo = new RefreshTokenUserInfo(user.getUsername());
        return gson.toJson(userInfo);
    }

    public static RefreshTokenUserInfo fromJson(String tokenPayload) {
        return gson.fromJson(tokenPayload, RefreshTokenUserInfo.class);
    }

    public String getUsername() {
        return username;
    }
}
