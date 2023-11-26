package com.drkcode.authapp.security;

import com.google.gson.Gson;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.List;

public class AccessTokenUserInfo {

    private static final Gson gson = new Gson();
    private final String username;
    private final List<String> roles;

    private AccessTokenUserInfo(String username, List<String> roles) {
        this.username = username;
        this.roles = roles;
    }

    public static String toJson(UserDetails user) {
        var userInfo = new AccessTokenUserInfo(user.getUsername(), user.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList());
        return gson.toJson(userInfo);
    }

    public static AccessTokenUserInfo fromJson(String tokenPayload) {
        return gson.fromJson(tokenPayload, AccessTokenUserInfo.class);
    }

    public String getUsername() {
        return username;
    }

    public List<String> getRoles() {
        return roles;
    }

}
