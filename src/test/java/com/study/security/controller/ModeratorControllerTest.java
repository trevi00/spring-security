package com.study.security.controller;

import com.study.security.entity.Role;
import com.study.security.entity.User;
import com.study.security.repository.UserRepository;
import com.study.security.security.UserPrincipal;
import com.study.security.security.jwt.JwtTokenProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import java.util.Set;

import static org.hamcrest.Matchers.hasSize;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Transactional
class ModeratorControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtTokenProvider tokenProvider;

    private User adminUser;
    private User moderatorUser;
    private User normalUser;
    private String adminToken;
    private String moderatorToken;
    private String userToken;

    @BeforeEach
    void setUp() {
        userRepository.deleteAll();

        // Create admin user
        adminUser = User.builder()
                .username("admin")
                .email("admin@example.com")
                .password(passwordEncoder.encode("Admin@1234"))
                .roles(Set.of(Role.ADMIN))
                .build();
        adminUser = userRepository.save(adminUser);

        // Create moderator user
        moderatorUser = User.builder()
                .username("moderator")
                .email("moderator@example.com")
                .password(passwordEncoder.encode("Moderator@1234"))
                .roles(Set.of(Role.MODERATOR))
                .build();
        moderatorUser = userRepository.save(moderatorUser);

        // Create normal user
        normalUser = User.builder()
                .username("user")
                .email("user@example.com")
                .password(passwordEncoder.encode("User@1234"))
                .roles(Set.of(Role.USER))
                .build();
        normalUser = userRepository.save(normalUser);

        // Generate tokens using UserPrincipal
        UserPrincipal adminPrincipal = UserPrincipal.create(adminUser);
        UsernamePasswordAuthenticationToken adminAuth =
                new UsernamePasswordAuthenticationToken(adminPrincipal, null, adminPrincipal.getAuthorities());
        adminToken = tokenProvider.generateToken(adminAuth);

        UserPrincipal moderatorPrincipal = UserPrincipal.create(moderatorUser);
        UsernamePasswordAuthenticationToken moderatorAuth =
                new UsernamePasswordAuthenticationToken(moderatorPrincipal, null, moderatorPrincipal.getAuthorities());
        moderatorToken = tokenProvider.generateToken(moderatorAuth);

        UserPrincipal userPrincipal = UserPrincipal.create(normalUser);
        UsernamePasswordAuthenticationToken userAuth =
                new UsernamePasswordAuthenticationToken(userPrincipal, null, userPrincipal.getAuthorities());
        userToken = tokenProvider.generateToken(userAuth);
    }

    @Test
    @DisplayName("신고 목록 조회 성공 - Moderator 권한")
    void getReports_AsModerator_Success() throws Exception {
        mockMvc.perform(get("/api/moderator/reports")
                        .header("Authorization", "Bearer " + moderatorToken))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(content().string("Reports functionality - to be implemented"));
    }

    @Test
    @DisplayName("신고 목록 조회 성공 - Admin 권한 (Admin은 Moderator 권한도 가짐)")
    void getReports_AsAdmin_Success() throws Exception {
        mockMvc.perform(get("/api/moderator/reports")
                        .header("Authorization", "Bearer " + adminToken))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(content().string("Reports functionality - to be implemented"));
    }

    @Test
    @DisplayName("신고 목록 조회 실패 - User 권한")
    void getReports_AsUser_Forbidden() throws Exception {
        mockMvc.perform(get("/api/moderator/reports")
                        .header("Authorization", "Bearer " + userToken))
                .andDo(print())
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("사용자 상태 변경 성공 - Moderator 권한")
    void updateUserStatus_AsModerator_Success() throws Exception {
        mockMvc.perform(put("/api/moderator/users/{userId}/status", normalUser.getId())
                        .header("Authorization", "Bearer " + moderatorToken)
                        .param("status", "SUSPENDED"))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(content().string("User status updated to: SUSPENDED"));
    }

    @Test
    @DisplayName("사용자 상태 변경 성공 - Admin 권한")
    void updateUserStatus_AsAdmin_Success() throws Exception {
        mockMvc.perform(put("/api/moderator/users/{userId}/status", normalUser.getId())
                        .header("Authorization", "Bearer " + adminToken)
                        .param("status", "ACTIVE"))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(content().string("User status updated to: ACTIVE"));
    }

    @Test
    @DisplayName("사용자 상태 변경 실패 - User 권한")
    void updateUserStatus_AsUser_Forbidden() throws Exception {
        mockMvc.perform(put("/api/moderator/users/{userId}/status", normalUser.getId())
                        .header("Authorization", "Bearer " + userToken)
                        .param("status", "SUSPENDED"))
                .andDo(print())
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("중재용 사용자 목록 조회 성공 - Moderator 권한")
    void getAllUsersForModeration_AsModerator_Success() throws Exception {
        mockMvc.perform(get("/api/moderator/users")
                        .header("Authorization", "Bearer " + moderatorToken))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", hasSize(3)));
    }

    @Test
    @DisplayName("중재용 사용자 목록 조회 성공 - Admin 권한")
    void getAllUsersForModeration_AsAdmin_Success() throws Exception {
        mockMvc.perform(get("/api/moderator/users")
                        .header("Authorization", "Bearer " + adminToken))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", hasSize(3)));
    }

    @Test
    @DisplayName("중재용 사용자 목록 조회 실패 - User 권한")
    void getAllUsersForModeration_AsUser_Forbidden() throws Exception {
        mockMvc.perform(get("/api/moderator/users")
                        .header("Authorization", "Bearer " + userToken))
                .andDo(print())
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("인증 없이 중재자 엔드포인트 접근 실패")
    void moderatorEndpoints_NoAuth_Unauthorized() throws Exception {
        mockMvc.perform(get("/api/moderator/reports"))
                .andDo(print())
                .andExpect(status().isUnauthorized());

        mockMvc.perform(put("/api/moderator/users/1/status")
                        .param("status", "SUSPENDED"))
                .andDo(print())
                .andExpect(status().isUnauthorized());

        mockMvc.perform(get("/api/moderator/users"))
                .andDo(print())
                .andExpect(status().isUnauthorized());
    }
}