package com.drkcode.authapp.controller;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/user")
public class UserController {

    @GetMapping
    public String getInfo() {
        var currentUser = SecurityContextHolder.getContext().getAuthentication().getPrincipal().toString();
        return String.format("Welcome, %s! You can access STANDARD USER resources.", currentUser);
    }
}
