package com.example.securitydemo.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collections;
import java.util.Map;

@RestController
public class OAuth2Controller {

    @GetMapping("/oauth2/redirect")
    public Map<String, String> handleOAuth2Redirect(@RequestParam("token") String token) {
        return Collections.singletonMap("token", token);
    }
}