package com.example.securitydemo.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.example.securitydemo.entity.UserEntity;

public interface UserRepository extends JpaRepository<UserEntity, String> {

    
}