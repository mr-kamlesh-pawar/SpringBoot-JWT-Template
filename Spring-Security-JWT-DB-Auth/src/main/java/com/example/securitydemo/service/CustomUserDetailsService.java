package com.example.securitydemo.service;

import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.example.securitydemo.entity.UserEntity;
import com.example.securitydemo.repository.UserRepository;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    @Autowired
    private UserRepository repo;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserEntity user = repo.findById(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));

        // Handle password for OAuth vs local users
        String password = user.isOAuthUser()
                ? "{noop}oauth-dummy-password"  // No password check for OAuth users
                : user.getPassword();           // Use encoded password for local users

        // Ensure roles exist
        List<GrantedAuthority> authorities = user.getRoles().stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());

        return new org.springframework.security.core.userdetails.User(
                user.getUsername(),
                password,
                authorities
        );
    }

    public UserDetails processOAuthPostLogin(String email, String provider) {
        UserEntity user = repo.findById(email).orElseGet(() -> {
            // Create new OAuth user
            UserEntity newUser = new UserEntity();
            newUser.setUsername(email);
            newUser.setOauthProvider(provider);
            newUser.setEnabled(true);
            newUser.setRoles(List.of("ROLE_USER")); // Default role
            return repo.save(newUser);
        });

        // Update provider if existing user
        if (user.getOauthProvider() == null) {
            user.setOauthProvider(provider);
            repo.save(user);
        }

        return loadUserByUsername(email);
    }
}