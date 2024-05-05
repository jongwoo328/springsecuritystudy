package com.example.springsecurity.test;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

@SpringBootApplication
public class SecurityStudyApplication {

    public static void main(String[] args) {
        SpringApplication.run(SecurityStudyApplication.class, args);
    }

}

