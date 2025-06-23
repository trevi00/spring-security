package com.study.security.controller;

import com.study.security.dto.UserResponse;
import com.study.security.security.CurrentUser;
import com.study.security.security.UserPrincipal;
import com.study.security.service.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/user")
@RequiredArgsConstructor
@SecurityRequirement(name = "bearerAuth")
@Tag(name = "사용자 API", description = "일반 사용자 권한이 필요한 API")
public class UserController {

    private final UserService userService;

    @Operation(summary = "내 정보 조회", description = "현재 로그인한 사용자의 정보를 조회합니다.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "조회 성공",
                    content = @Content(schema = @Schema(implementation = UserResponse.class))),
            @ApiResponse(responseCode = "401", description = "인증 실패"),
            @ApiResponse(responseCode = "403", description = "권한 없음")
    })
    @GetMapping("/profile")
    public ResponseEntity<UserResponse> getCurrentUser(
            @Parameter(hidden = true) @CurrentUser UserPrincipal currentUser) {
        UserResponse userResponse = userService.getCurrentUser(currentUser);
        return ResponseEntity.ok(userResponse);
    }

    @Operation(summary = "이메일 수정", description = "현재 로그인한 사용자의 이메일을 수정합니다.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "수정 성공",
                    content = @Content(schema = @Schema(implementation = UserResponse.class))),
            @ApiResponse(responseCode = "401", description = "인증 실패"),
            @ApiResponse(responseCode = "500", description = "중복된 이메일")
    })
    @PutMapping("/profile")
    public ResponseEntity<UserResponse> updateProfile(
            @Parameter(hidden = true) @CurrentUser UserPrincipal currentUser,
            @Parameter(description = "새로운 이메일 주소", required = true, example = "newemail@example.com")
            @RequestParam String email) {
        UserResponse userResponse = userService.updateProfile(currentUser, email);
        return ResponseEntity.ok(userResponse);
    }

    @Operation(summary = "계정 삭제", description = "현재 로그인한 사용자의 계정을 삭제합니다.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "삭제 성공"),
            @ApiResponse(responseCode = "401", description = "인증 실패")
    })
    @DeleteMapping("/account")
    public ResponseEntity<String> deleteAccount(
            @Parameter(hidden = true) @CurrentUser UserPrincipal currentUser) {
        userService.deleteUser(currentUser.getId());
        return ResponseEntity.ok("Account deleted successfully");
    }
}