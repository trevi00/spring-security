package com.study.security.service;

import com.study.security.dto.LoginRequest;
import com.study.security.dto.SignUpRequest;
import com.study.security.entity.User;
import com.study.security.repository.UserRepository;
import com.study.security.security.jwt.JwtTokenProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @Mock
    private AuthenticationManager authenticationManager;

    @Mock
    private UserRepository userRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private JwtTokenProvider tokenProvider;

    @InjectMocks
    private AuthService authService;

    private SignUpRequest signUpRequest;

    @BeforeEach
    void setUp() {
        signUpRequest = new SignUpRequest();
        signUpRequest.setUsername("testuser");
        signUpRequest.setEmail("test@example.com");
        signUpRequest.setPassword("Test@1234");
    }

    @Test
    @DisplayName("회원가입 성공")
    void registerUser_Success() {
        // given
        given(userRepository.existsByUsername(anyString())).willReturn(false);
        given(userRepository.existsByEmail(anyString())).willReturn(false);
        given(passwordEncoder.encode(anyString())).willReturn("encodedPassword");
        given(userRepository.save(any(User.class))).willAnswer(invocation -> invocation.getArgument(0));

        // when
        String result = authService.registerUser(signUpRequest);

        // then
        assertThat(result).isEqualTo("User registered successfully!");
        verify(userRepository, times(1)).save(any(User.class));
    }

    @Test
    @DisplayName("회원가입 실패 - 중복 username")
    void registerUser_DuplicateUsername_ThrowsException() {
        // given
        given(userRepository.existsByUsername(anyString())).willReturn(true);

        // when & then
        assertThatThrownBy(() -> authService.registerUser(signUpRequest))
                .isInstanceOf(RuntimeException.class)
                .hasMessage("Username is already taken!");

        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    @DisplayName("회원가입 실패 - 중복 email")
    void registerUser_DuplicateEmail_ThrowsException() {
        // given
        given(userRepository.existsByUsername(anyString())).willReturn(false);
        given(userRepository.existsByEmail(anyString())).willReturn(true);

        // when & then
        assertThatThrownBy(() -> authService.registerUser(signUpRequest))
                .isInstanceOf(RuntimeException.class)
                .hasMessage("Email is already in use!");

        verify(userRepository, never()).save(any(User.class));
    }
}