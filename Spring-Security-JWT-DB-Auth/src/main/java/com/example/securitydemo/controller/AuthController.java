package com.example.securitydemo.controller;

import com.example.securitydemo.dto.LoginRequest;
import com.example.securitydemo.dto.LoginResponse;
import com.example.securitydemo.dto.RegisterRequest;
import com.example.securitydemo.entity.UserEntity;
import com.example.securitydemo.repository.UserRepository;
import com.example.securitydemo.security.JwtUtils;
import com.example.securitydemo.service.CustomUserDetailsService;

import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
public class AuthController {

    @Autowired
    private JwtUtils jwtUtils;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private CustomUserDetailsService userService;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder encoder;


// Simple
// @PostMapping("/register")
//    public ResponseEntity<?> register(@RequestBody RegisterRequest request) {
//        if (userRepository.existsById(request.getUsername())) {
//            return ResponseEntity.badRequest().body("User already exists");
//        }
//
//        UserEntity user = new UserEntity();
//        user.setUsername(request.getUsername());
//        user.setPassword(encoder.encode(request.getPassword()));
//        user.setRoles(request.getRoles());
//
//        userRepository.save(user);
//        return ResponseEntity.ok("Registered");
//    }
//
//
//
//
//    @PostMapping("/signin")
//    public ResponseEntity<?> authenticateUser(@RequestBody LoginRequest loginRequest) {
//        Authentication authentication;
//        try {
//            authentication = authenticationManager
//                    .authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));
//        } catch (AuthenticationException exception) {
//            Map<String, Object> map = new HashMap<>();
//            map.put("message", "Bad credentials");
//            map.put("status", false);
//            return new ResponseEntity<Object>(map, HttpStatus.NOT_FOUND);
//        }
//
//        SecurityContextHolder.getContext().setAuthentication(authentication);
//
//        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
//
//        String jwtToken = jwtUtils.generateTokenFromUsername(userDetails);
//
//        List<String> roles = userDetails.getAuthorities().stream()
//                .map(item -> item.getAuthority())
//                .collect(Collectors.toList());
//
//        LoginResponse response = new LoginResponse(userDetails.getUsername(), roles, jwtToken);
//
//        return ResponseEntity.ok(response);
//    }


    //With Proper Validation
    @PostMapping("/register")
    public ResponseEntity<?> register(@Valid @RequestBody RegisterRequest request,
                                      BindingResult bindingResult) {
        // Validate request
        if (bindingResult.hasErrors()) {
            Map<String, String> errors = new HashMap<>();
            bindingResult.getFieldErrors().forEach(error ->
                    errors.put(error.getField(), error.getDefaultMessage()));
            return ResponseEntity.badRequest().body(errors);
        }

        // Check if user exists
        if (userRepository.existsById(request.getUsername())) {
            UserEntity existingUser = userRepository.findById(request.getUsername()).orElse(null);
            if (existingUser != null && existingUser.getOauthProvider() != null) {
                return ResponseEntity.badRequest().body(
                        Map.of("message", "User already exists via " + existingUser.getOauthProvider() + " OAuth"));
            }
            return ResponseEntity.badRequest().body(Map.of("message", "Username already taken"));
        }

        // Validate password strength
        if (!isPasswordValid(request.getPassword())) {
            return ResponseEntity.badRequest().body(
                    Map.of("message", "Password must be 8-20 chars with at least 1 digit, 1 letter, and 1 special char"));
        }

        // Validate roles
        if (request.getRoles() == null || request.getRoles().isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("message", "At least one role must be specified"));
        }

        // Create new user
        UserEntity user = new UserEntity();
        user.setUsername(request.getUsername());
        user.setPassword(encoder.encode(request.getPassword()));
        user.setRoles(request.getRoles());
        user.setEnabled(true);

        userRepository.save(user);
        return ResponseEntity.ok(Map.of("message", "User registered successfully"));
    }

    //LOGIN
    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest,
                                              BindingResult bindingResult) {
        // Validate request
        if (bindingResult.hasErrors()) {
            Map<String, String> errors = new HashMap<>();
            bindingResult.getFieldErrors().forEach(error ->
                    errors.put(error.getField(), error.getDefaultMessage()));
            return ResponseEntity.badRequest().body(errors);
        }

        // Check if user exists
        if (!userRepository.existsById(loginRequest.getUsername())) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(Map.of("message", "User not found"));
        }

        // Check if account is OAuth-based
        UserEntity user = userRepository.findById(loginRequest.getUsername()).orElse(null);
        if (user != null && user.getOauthProvider() != null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(Map.of("message", "Please login via " + user.getOauthProvider()));
        }

        // Authenticate
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            loginRequest.getUsername(),
                            loginRequest.getPassword()));

            SecurityContextHolder.getContext().setAuthentication(authentication);
            UserDetails userDetails = (UserDetails) authentication.getPrincipal();

            String jwtToken = jwtUtils.generateTokenFromUsername(userDetails);

            List<String> roles = userDetails.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.toList());

            return ResponseEntity.ok(new LoginResponse(
                    userDetails.getUsername(),
                    roles,
                    jwtToken));

        } catch (AuthenticationException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("message", "Invalid credentials"));
        }
    }

    // Password validation helper
    private boolean isPasswordValid(String password) {
        if (password == null || password.length() < 8 || password.length() > 20) {
            return false;
        }
        // At least 1 digit, 1 letter, 1 special char
        String pattern = "^(?=.*[0-9])(?=.*[a-zA-Z])(?=.*[@#$%^&+=!])(?=\\S+$).{8,20}$";
        return password.matches(pattern);
    }
}
