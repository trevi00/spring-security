package com.study.security.service;

import com.study.security.dto.UserResponse;
import com.study.security.entity.Role;
import com.study.security.entity.User;
import com.study.security.repository.UserRepository;
import com.study.security.security.UserPrincipal;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class UserService {

    private final UserRepository userRepository;

    @PreAuthorize("hasRole('USER')")
    public UserResponse getCurrentUser(UserPrincipal currentUser) {
        return userRepository.findById(currentUser.getId())
                .map(UserResponse::from)
                .orElseThrow(() -> new RuntimeException("User not found"));
    }

    @PreAuthorize("hasAnyRole('ADMIN', 'MODERATOR')")
    @Transactional(readOnly = true)
    public List<UserResponse> getAllUsers() {
        return userRepository.findAll().stream()
                .map(UserResponse::from)
                .collect(Collectors.toList());
    }

    @PreAuthorize("hasRole('ADMIN')")
    @Transactional
    public UserResponse updateUserRole(Long userId, Role role) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));

        // 기존 역할을 유지하면서 새 역할 추가
        user.addRole(role);
        User updatedUser = userRepository.save(user);

        log.info("User {} role updated to include {}", user.getUsername(), role);

        return UserResponse.from(updatedUser);
    }

    @PreAuthorize("hasRole('ADMIN') or #userId == authentication.principal.id")
    @Transactional
    public void deleteUser(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));

        userRepository.delete(user);

        log.info("User {} deleted", user.getUsername());
    }

    @PreAuthorize("hasRole('USER')")
    @Transactional
    public UserResponse updateProfile(UserPrincipal currentUser, String email) {
        User user = userRepository.findById(currentUser.getId())
                .orElseThrow(() -> new RuntimeException("User not found"));

        if (!user.getEmail().equals(email) && userRepository.existsByEmail(email)) {
            throw new RuntimeException("Email is already in use!");
        }

        user.setEmail(email);
        User updatedUser = userRepository.save(user);

        return UserResponse.from(updatedUser);
    }
}