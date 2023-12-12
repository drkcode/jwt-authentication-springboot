package com.drkcode.authapp.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@Configuration
public class InMemoryUserDetailsServiceConfig {

    @Bean
    public InMemoryUserDetailsManager userDetails(PasswordEncoder passwordEncoder) {
        var user1 = User.withUsername("darlisson@email.com")
                .password(passwordEncoder.encode("1234"))
                .roles("ADMIN").build();

        var user2 = User
                .withUsername("johndoe@email.com")
                .password(passwordEncoder.encode("1234"))
                .build();

        var userDetailsManager = new InMemoryUserDetailsManager();
        userDetailsManager.createUser(user1);
        userDetailsManager.createUser(user2);
        return userDetailsManager;
    }
}
