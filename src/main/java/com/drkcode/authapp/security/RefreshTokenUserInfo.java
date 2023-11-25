package com.drkcode.authapp.security;

import com.google.gson.Gson;
import org.springframework.security.core.userdetails.UserDetails;

public class RefreshTokenUserInfo {

    private final String username;

    private RefreshTokenUserInfo(String username) {
        this.username = username;
    }

    public static String toJson(UserDetails user) {
        var gson = new Gson();
        var userInfo = new RefreshTokenUserInfo(user.getUsername());
        return gson.toJson(userInfo);
    }

    public static RefreshTokenUserInfo fromJson(String tokenPayload) {
        var gson = new Gson();
        return gson.fromJson(tokenPayload, RefreshTokenUserInfo.class);
    }

    public String getUsername() {
        return username;
    }
}
