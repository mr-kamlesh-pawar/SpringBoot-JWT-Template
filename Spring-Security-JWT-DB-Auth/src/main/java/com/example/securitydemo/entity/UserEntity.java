package com.example.securitydemo.entity;

import java.util.ArrayList;
import java.util.List;

import jakarta.persistence.*;


@Entity
@Table(name = "users")
public class UserEntity {
    @Id
    private String username;

    private String password; //nullable

    private boolean enabled = true;

    @Column(name = "oauth_provider")
    private String oauthProvider; // "google", "github", or null for local users



    @ElementCollection(fetch = FetchType.EAGER)
    private List<String> roles = new ArrayList<>(); // Initialize empty list

    // Add helper methods
    public boolean isOAuthUser() {
        return this.oauthProvider != null;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public List<String> getRoles() {
        return roles;
    }

    public void setRoles(List<String> roles) {
        this.roles = roles;
    }

    public String getOauthProvider() {
        return oauthProvider;
    }

    public void setOauthProvider(String oauthProvider) {
        this.oauthProvider = oauthProvider;
    }
}
