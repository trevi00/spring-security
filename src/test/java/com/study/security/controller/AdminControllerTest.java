package com.study.security.controller;

import com.study.security.entity.Role;
import com.study.security.entity.User;
import com.study.security.repository.UserRepository;
import com.study.security.security.jwt.JwtTokenProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Set;

import static org.hamcrest.Matchers.hasSize;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Transactional
class AdminControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtTokenProvider tokenProvider;

    private User adminUser;
    private User normalUser;
    private String adminToken;
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

        // Create normal user
        normalUser = User.builder()
                .username("user")
                .email("user@example.com")
                .password(passwordEncoder.encode("User@1234"))
                .roles(Set.of(Role.USER))
                .build();
        normalUser = userRepository.save(normalUser);

        // Generate tokens
        UsernamePasswordAuthenticationToken adminAuth =
                new UsernamePasswordAuthenticationToken(
                        adminUser.getId(),
                        null,
                        List.of(new SimpleGrantedAuthority("ROLE_ADMIN"))
                );
        adminToken = tokenProvider.generateToken(adminAuth);

        UsernamePasswordAuthenticationToken userAuth =
                new UsernamePasswordAuthenticationToken(
                        normalUser.getId(),
                        null,
                        List.of(new SimpleGrantedAuthority("ROLE_USER"))
                );
        userToken = tokenProvider.generateToken(userAuth);
    }

    @Test
    @DisplayName("전체 사용자 조회 성공 - Admin 권한")
    void getAllUsers_AsAdmin_Success() throws Exception {
        mockMvc.perform(get("/api/admin/users")
                        .header("Authorization", "Bearer " + adminToken))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", hasSize(2)));
    }

    @Test
    @DisplayName("전체 사용자 조회 실패 - User 권한")
    void getAllUsers_AsUser_Forbidden() throws Exception {
        mockMvc.perform(get("/api/admin/users")
                        .header("Authorization", "Bearer " + userToken))
                .andDo(print())
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("사용자 권한 변경 성공")
    void updateUserRole_Success() throws Exception {
        mockMvc.perform(put("/api/admin/users/{userId}/role", normalUser.getId())
                        .header("Authorization", "Bearer " + adminToken)
                        .param("role", "MODERATOR"))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.roles", hasSize(2)));
    }

    @Test
    @DisplayName("사용자 삭제 성공")
    void deleteUser_Success() throws Exception {
        mockMvc.perform(delete("/api/admin/users/{userId}", normalUser.getId())
                        .header("Authorization", "Bearer " + adminToken))
                .andDo(print())
                .andExpect(status().isOk());
    }
}