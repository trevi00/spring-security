package com.study.security.controller;

import com.study.security.dto.UserResponse;
import com.study.security.security.CurrentUser;
import com.study.security.security.UserPrincipal;
import com.study.security.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/user")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    @GetMapping("/profile")
    public ResponseEntity<UserResponse> getCurrentUser(@CurrentUser UserPrincipal currentUser) {
        UserResponse userResponse = userService.getCurrentUser(currentUser);
        return ResponseEntity.ok(userResponse);
    }

    @PutMapping("/profile")
    public ResponseEntity<UserResponse> updateProfile(@CurrentUser UserPrincipal currentUser,
                                                      @RequestParam String email) {
        UserResponse userResponse = userService.updateProfile(currentUser, email);
        return ResponseEntity.ok(userResponse);
    }

    @DeleteMapping("/account")
    public ResponseEntity<String> deleteAccount(@CurrentUser UserPrincipal currentUser) {
        userService.deleteUser(currentUser.getId());
        return ResponseEntity.ok("Account deleted successfully");
    }
}