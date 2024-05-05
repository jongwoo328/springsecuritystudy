package com.example.springsecurity.test.learningspringsecurity.resources;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloWorldResource {
    @GetMapping("/hello-world")
    public String helloWorld() {
        return "Hello World! v3";
    }
}
