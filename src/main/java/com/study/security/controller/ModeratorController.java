package com.study.security.controller;

import com.study.security.dto.UserResponse;
import com.study.security.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/moderator")
@RequiredArgsConstructor
public class ModeratorController {

    private final UserService userService;

    @GetMapping("/reports")
    public ResponseEntity<String> getReports() {
        // 임시 구현 - 실제로는 신고 관리 서비스가 필요
        return ResponseEntity.ok("Reports functionality - to be implemented");
    }

    @PutMapping("/users/{userId}/status")
    public ResponseEntity<String> updateUserStatus(@PathVariable Long userId,
                                                   @RequestParam String status) {
        // 임시 구현 - 실제로는 사용자 상태 관리 로직이 필요
        return ResponseEntity.ok("User status updated to: " + status);
    }

    @GetMapping("/users")
    public ResponseEntity<List<UserResponse>> getAllUsersForModeration() {
        List<UserResponse> users = userService.getAllUsers();
        return ResponseEntity.ok(users);
    }
}