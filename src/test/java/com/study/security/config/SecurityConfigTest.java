package com.study.security.config;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class SecurityConfigTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    @DisplayName("인증 없이 public 엔드포인트 접근 가능")
    void publicEndpoint_NoAuth_Success() throws Exception {
        mockMvc.perform(get("/api/public/test"))
                .andExpect(status().isNotFound()); // 엔드포인트가 없어서 404, 하지만 401은 아님
    }

    @Test
    @DisplayName("인증 없이 protected 엔드포인트 접근 불가")
    void protectedEndpoint_NoAuth_Unauthorized() throws Exception {
        mockMvc.perform(get("/api/user/profile"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("인증 API는 인증 없이 접근 가능")
    void authEndpoints_NoAuth_Success() throws Exception {
        mockMvc.perform(post("/api/auth/signin")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isBadRequest()); // Body가 잘못되어서 400, 하지만 401은 아님

        mockMvc.perform(post("/api/auth/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isBadRequest()); // Body가 잘못되어서 400, 하지만 401은 아님
    }
}