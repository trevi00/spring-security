package com.study.security.controller;

import com.study.security.dto.UserResponse;
import com.study.security.entity.Role;
import com.study.security.service.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.ArraySchema;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/admin")
@RequiredArgsConstructor
@SecurityRequirement(name = "bearerAuth")
@Tag(name = "관리자 API", description = "관리자 권한이 필요한 API")
public class AdminController {

    private final UserService userService;

    @Operation(summary = "전체 사용자 조회", description = "시스템의 모든 사용자 목록을 조회합니다.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "조회 성공",
                    content = @Content(array = @ArraySchema(schema = @Schema(implementation = UserResponse.class)))),
            @ApiResponse(responseCode = "401", description = "인증 실패"),
            @ApiResponse(responseCode = "403", description = "권한 없음")
    })
    @GetMapping("/users")
    public ResponseEntity<List<UserResponse>> getAllUsers() {
        List<UserResponse> users = userService.getAllUsers();
        return ResponseEntity.ok(users);
    }

    @Operation(summary = "사용자 권한 변경", description = "특정 사용자의 권한을 추가합니다.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "권한 변경 성공",
                    content = @Content(schema = @Schema(implementation = UserResponse.class))),
            @ApiResponse(responseCode = "401", description = "인증 실패"),
            @ApiResponse(responseCode = "403", description = "권한 없음"),
            @ApiResponse(responseCode = "404", description = "사용자를 찾을 수 없음")
    })
    @PutMapping("/users/{userId}/role")
    public ResponseEntity<UserResponse> updateUserRole(
            @Parameter(description = "사용자 ID", required = true, example = "1")
            @PathVariable Long userId,
            @Parameter(description = "추가할 권한", required = true, schema = @Schema(implementation = Role.class))
            @RequestParam Role role) {
        UserResponse userResponse = userService.updateUserRole(userId, role);
        return ResponseEntity.ok(userResponse);
    }

    @Operation(summary = "사용자 삭제", description = "특정 사용자를 시스템에서 삭제합니다.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "삭제 성공"),
            @ApiResponse(responseCode = "401", description = "인증 실패"),
            @ApiResponse(responseCode = "403", description = "권한 없음"),
            @ApiResponse(responseCode = "404", description = "사용자를 찾을 수 없음")
    })
    @DeleteMapping("/users/{userId}")
    public ResponseEntity<String> deleteUser(
            @Parameter(description = "사용자 ID", required = true, example = "1")
            @PathVariable Long userId) {
        userService.deleteUser(userId);
        return ResponseEntity.ok("User deleted successfully");
    }
}