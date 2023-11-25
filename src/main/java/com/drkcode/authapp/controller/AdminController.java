package com.drkcode.authapp.controller;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/admin")
public class AdminController {

    @GetMapping
    public String adminUser() {
        var currentUser = SecurityContextHolder.getContext().getAuthentication().getPrincipal().toString();
        return String.format("Welcome, %s! Your are an ADMIN user.", currentUser);
    }
}
