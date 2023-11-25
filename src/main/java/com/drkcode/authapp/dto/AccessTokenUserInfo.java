package com.drkcode.authapp.dto;

import com.google.gson.Gson;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.List;

public class AccessTokenUserInfo {

    private final String username;
    private final List<String> roles;

    private AccessTokenUserInfo(String username, List<String> roles) {
        this.username = username;
        this.roles = roles;
    }

    public static String toJson(UserDetails user) {
        var gson = new Gson();
        var userInfo = new AccessTokenUserInfo(user.getUsername(), user.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList());
        return gson.toJson(userInfo);
    }

    public static AccessTokenUserInfo fromJson(String tokenPayload) {
        var gson = new Gson();
        return gson.fromJson(tokenPayload, AccessTokenUserInfo.class);
    }

    public String getUsername() {
        return username;
    }

    public List<String> getRoles() {
        return roles;
    }

}
