package com.study.security.debug;

import com.study.security.entity.Role;
import com.study.security.entity.User;
import com.study.security.repository.UserRepository;
import com.study.security.security.UserPrincipal;
import com.study.security.security.jwt.JwtTokenProvider;
import com.study.security.service.UserService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.transaction.annotation.Transactional;

import java.util.Set;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Transactional
public class DebugTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtTokenProvider tokenProvider;

    @Autowired
    private UserService userService;

    private User adminUser;
    private User normalUser;
    private String adminToken;

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

        // Generate admin token
        UserPrincipal adminPrincipal = UserPrincipal.create(adminUser);
        UsernamePasswordAuthenticationToken adminAuth =
                new UsernamePasswordAuthenticationToken(adminPrincipal, null, adminPrincipal.getAuthorities());
        adminToken = tokenProvider.generateToken(adminAuth);
    }

    @Test
    void debugRoleUpdate() throws Exception {
        System.out.println("=== Before role update ===");
        System.out.println("Normal user roles: " + normalUser.getRoles());

        MvcResult result = mockMvc.perform(put("/api/admin/users/{userId}/role", normalUser.getId())
                        .header("Authorization", "Bearer " + adminToken)
                        .param("role", "MODERATOR"))
                .andDo(print())
                .andReturn();

        System.out.println("=== Response Status: " + result.getResponse().getStatus());
        System.out.println("=== Response Body: " + result.getResponse().getContentAsString());

        // Refresh user from database
        User updatedUser = userRepository.findById(normalUser.getId()).orElse(null);
        System.out.println("=== After role update ===");
        System.out.println("Updated user roles: " + (updatedUser != null ? updatedUser.getRoles() : "null"));
    }

    @Test
    void debugEmailUpdate() throws Exception {
        UserPrincipal userPrincipal = UserPrincipal.create(normalUser);
        UsernamePasswordAuthenticationToken userAuth =
                new UsernamePasswordAuthenticationToken(userPrincipal, null, userPrincipal.getAuthorities());
        String userToken = tokenProvider.generateToken(userAuth);

        System.out.println("=== Before email update ===");
        System.out.println("Normal user email: " + normalUser.getEmail());

        MvcResult result = mockMvc.perform(put("/api/user/profile")
                        .header("Authorization", "Bearer " + userToken)
                        .param("email", "newemail@example.com"))
                .andDo(print())
                .andReturn();

        System.out.println("=== Response Status: " + result.getResponse().getStatus());
        System.out.println("=== Response Body: " + result.getResponse().getContentAsString());

        // Refresh user from database
        User updatedUser = userRepository.findById(normalUser.getId()).orElse(null);
        System.out.println("=== After email update ===");
        System.out.println("Updated user email: " + (updatedUser != null ? updatedUser.getEmail() : "null"));
    }
}