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

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Transactional
class UserControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtTokenProvider tokenProvider;

    private User testUser;
    private String userToken;

    @BeforeEach
    void setUp() {
        userRepository.deleteAll();

        // Create test user
        testUser = User.builder()
                .username("testuser")
                .email("test@example.com")
                .password(passwordEncoder.encode("Test@1234"))
                .roles(Set.of(Role.USER))
                .build();
        testUser = userRepository.save(testUser);

        // Generate JWT token using UserPrincipal
        UserPrincipal userPrincipal = UserPrincipal.create(testUser);
        UsernamePasswordAuthenticationToken authentication =
                new UsernamePasswordAuthenticationToken(userPrincipal, null, userPrincipal.getAuthorities());
        userToken = tokenProvider.generateToken(authentication);
    }

    @Test
    @DisplayName("프로필 조회 성공")
    void getProfile_Success() throws Exception {
        mockMvc.perform(get("/api/user/profile")
                        .header("Authorization", "Bearer " + userToken))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("testuser"))
                .andExpect(jsonPath("$.email").value("test@example.com"));
    }

    @Test
    @DisplayName("프로필 조회 실패 - 인증 없음")
    void getProfile_NoAuth_Unauthorized() throws Exception {
        mockMvc.perform(get("/api/user/profile"))
                .andDo(print())
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("이메일 업데이트 성공")
    void updateEmail_Success() throws Exception {
        System.out.println("User initial email: " + testUser.getEmail());

        mockMvc.perform(put("/api/user/profile")
                        .header("Authorization", "Bearer " + userToken)
                        .param("email", "newemail@example.com"))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value("newemail@example.com"))
                .andExpect(jsonPath("$.username").value("testuser"));
    }

    @Test
    @DisplayName("이메일 업데이트 실패 - 인증 없음")
    void updateEmail_NoAuth_Unauthorized() throws Exception {
        mockMvc.perform(put("/api/user/profile")
                        .param("email", "newemail@example.com"))
                .andDo(print())
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("계정 삭제 성공")
    void deleteAccount_Success() throws Exception {
        mockMvc.perform(delete("/api/user/account")
                        .header("Authorization", "Bearer " + userToken))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(content().string("Account deleted successfully"));
    }

    @Test
    @DisplayName("계정 삭제 실패 - 인증 없음")
    void deleteAccount_NoAuth_Unauthorized() throws Exception {
        mockMvc.perform(delete("/api/user/account"))
                .andDo(print())
                .andExpect(status().isUnauthorized());
    }
}