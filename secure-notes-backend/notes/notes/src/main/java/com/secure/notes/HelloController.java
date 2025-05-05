package com.secure.notes;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloController {

    @GetMapping("/hello")
    public String hello() {
        return "Hello, World!";
    }

    @GetMapping("/hello2")
    public String hello2() {
        return "Hello, World! 2";
    }

    @GetMapping("/contact")
    public String contact() {
        return "Contact us at";
    }
}
