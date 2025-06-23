# Spring Security 학습 프로젝트 - 회원 관리 시스템

## 프로젝트 개요
Spring Security의 핵심 개념을 이해하고 구현 능력을 입증하기 위한 회원 관리 시스템입니다.

### 주요 학습 목표
1. **JWT 기반 인증/인가**
    - Stateless 인증 시스템 구현
    - Access Token 발급 및 검증
    - Token 기반 사용자 인증

2. **역할 기반 접근 제어(RBAC)**
    - 다중 사용자 역할 구현 (USER, ADMIN, MODERATOR)
    - 엔드포인트별 권한 설정
    - Method Level Security

3. **비밀번호 암호화**
    - BCrypt를 이용한 단방향 암호화
    - 비밀번호 강도 검증
    - 안전한 비밀번호 정책 구현

## 프로젝트 구조

```
spring-security-demo/
├── src/main/java/com/study/security/
│   ├── config/
│   │   ├── SecurityConfig.java
│   │   ├── JwtConfig.java
│   │   └── PasswordEncoderConfig.java
│   ├── security/
│   │   ├── jwt/
│   │   │   ├── JwtTokenProvider.java
│   │   │   ├── JwtAuthenticationFilter.java
│   │   │   └── JwtAuthenticationEntryPoint.java
│   │   └── CustomUserDetailsService.java
│   ├── controller/
│   │   ├── AuthController.java
│   │   ├── UserController.java
│   │   └── AdminController.java
│   ├── service/
│   │   ├── AuthService.java
│   │   └── UserService.java
│   ├── repository/
│   │   └── UserRepository.java
│   ├── entity/
│   │   ├── User.java
│   │   └── Role.java
│   └── dto/
│       ├── LoginRequest.java
│       ├── SignUpRequest.java
│       ├── JwtResponse.java
│       └── UserResponse.java
└── src/main/resources/
    └── application.yml
```

## 핵심 구현 내용

### 1. JWT 토큰 기반 인증

```java
// JwtTokenProvider.java
@Component
public class JwtTokenProvider {
    @Value("${jwt.secret}")
    private String jwtSecret;
    
    @Value("${jwt.expiration}")
    private int jwtExpiration;
    
    public String generateToken(Authentication authentication) {
        UserPrincipal userPrincipal = (UserPrincipal) authentication.getPrincipal();
        
        Date expiryDate = new Date(System.currentTimeMillis() + jwtExpiration);
        
        return Jwts.builder()
                .setSubject(userPrincipal.getId().toString())
                .setIssuedAt(new Date())
                .setExpiration(expiryDate)
                .signWith(SignatureAlgorithm.HS512, jwtSecret)
                .compact();
    }
    
    public Long getUserIdFromJWT(String token) {
        Claims claims = Jwts.parser()
                .setSigningKey(jwtSecret)
                .parseClaimsJws(token)
                .getBody();
                
        return Long.parseLong(claims.getSubject());
    }
    
    public boolean validateToken(String authToken) {
        try {
            Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(authToken);
            return true;
        } catch (SignatureException ex) {
            log.error("Invalid JWT signature");
        } catch (MalformedJwtException ex) {
            log.error("Invalid JWT token");
        } catch (ExpiredJwtException ex) {
            log.error("Expired JWT token");
        } catch (UnsupportedJwtException ex) {
            log.error("Unsupported JWT token");
        } catch (IllegalArgumentException ex) {
            log.error("JWT claims string is empty");
        }
        return false;
    }
}
```

### 2. 역할 기반 접근 제어 (RBAC)

```java
// SecurityConfig.java
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(
    securedEnabled = true,
    jsr250Enabled = true,
    prePostEnabled = true
)
public class SecurityConfig {
    
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .cors()
            .and()
            .csrf().disable()
            .exceptionHandling()
                .authenticationEntryPoint(unauthorizedHandler)
            .and()
            .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            .and()
            .authorizeHttpRequests()
                .requestMatchers("/api/auth/**").permitAll()
                .requestMatchers("/api/public/**").permitAll()
                .requestMatchers("/api/user/**").hasRole("USER")
                .requestMatchers("/api/moderator/**").hasRole("MODERATOR")
                .requestMatchers("/api/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated();
                
        http.addFilterBefore(jwtAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);
        
        return http.build();
    }
}
```

### 3. 비밀번호 암호화

```java
// PasswordEncoderConfig.java
@Configuration
public class PasswordEncoderConfig {
    
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12); // strength = 12
    }
}

// AuthService.java
@Service
public class AuthService {
    @Autowired
    private PasswordEncoder passwordEncoder;
    
    public User registerUser(SignUpRequest signUpRequest) {
        // 비밀번호 강도 검증
        validatePasswordStrength(signUpRequest.getPassword());
        
        // 비밀번호 암호화
        String encodedPassword = passwordEncoder.encode(signUpRequest.getPassword());
        
        User user = new User();
        user.setUsername(signUpRequest.getUsername());
        user.setEmail(signUpRequest.getEmail());
        user.setPassword(encodedPassword);
        user.setRoles(Set.of(Role.USER));
        
        return userRepository.save(user);
    }
    
    private void validatePasswordStrength(String password) {
        // 최소 8자, 대문자, 소문자, 숫자, 특수문자 포함
        String passwordPattern = "^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=])(?=\\S+$).{8,}$";
        
        if (!password.matches(passwordPattern)) {
            throw new BadRequestException("비밀번호는 8자 이상이며, 대소문자, 숫자, 특수문자를 포함해야 합니다.");
        }
    }
}
```

## API 엔드포인트

### 인증 관련 (공개)
- `POST /api/auth/signup` - 회원가입
- `POST /api/auth/login` - 로그인
- `POST /api/auth/refresh` - 토큰 갱신

### 사용자 권한 필요
- `GET /api/user/profile` - 내 정보 조회
- `PUT /api/user/profile` - 내 정보 수정
- `DELETE /api/user/account` - 회원 탈퇴

### 관리자 권한 필요
- `GET /api/admin/users` - 전체 사용자 조회
- `PUT /api/admin/users/{id}/role` - 사용자 권한 변경
- `DELETE /api/admin/users/{id}` - 사용자 삭제

### 중재자 권한 필요
- `GET /api/moderator/reports` - 신고 목록 조회
- `PUT /api/moderator/users/{id}/status` - 사용자 상태 변경

## 보안 기능 구현

### 1. JWT 필터 체인
```java
// JwtAuthenticationFilter.java
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    @Autowired
    private JwtTokenProvider tokenProvider;
    
    @Autowired
    private CustomUserDetailsService customUserDetailsService;
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, 
                                  HttpServletResponse response, 
                                  FilterChain filterChain) throws ServletException, IOException {
        try {
            String jwt = getJwtFromRequest(request);
            
            if (StringUtils.hasText(jwt) && tokenProvider.validateToken(jwt)) {
                Long userId = tokenProvider.getUserIdFromJWT(jwt);
                
                UserDetails userDetails = customUserDetailsService.loadUserById(userId);
                UsernamePasswordAuthenticationToken authentication = 
                    new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        } catch (Exception ex) {
            logger.error("Could not set user authentication in security context", ex);
        }
        
        filterChain.doFilter(request, response);
    }
}
```

### 2. Method Level Security
```java
// UserService.java
@Service
public class UserService {
    
    @PreAuthorize("hasRole('USER')")
    public UserResponse getCurrentUser(@AuthenticationPrincipal UserPrincipal currentUser) {
        return userRepository.findById(currentUser.getId())
            .map(this::convertToResponse)
            .orElseThrow(() -> new ResourceNotFoundException("User not found"));
    }
    
    @PreAuthorize("hasRole('ADMIN')")
    public List<UserResponse> getAllUsers() {
        return userRepository.findAll().stream()
            .map(this::convertToResponse)
            .collect(Collectors.toList());
    }
    
    @PreAuthorize("hasRole('ADMIN') or #userId == authentication.principal.id")
    public void deleteUser(Long userId) {
        userRepository.deleteById(userId);
    }
}
```

### 3. 보안 예외 처리
```java
// JwtAuthenticationEntryPoint.java
@Component
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {
    
    @Override
    public void commence(HttpServletRequest httpServletRequest,
                         HttpServletResponse httpServletResponse,
                         AuthenticationException e) throws IOException {
        httpServletResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized");
    }
}

// GlobalExceptionHandler.java
@RestControllerAdvice
public class GlobalExceptionHandler {
    
    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<?> handleAccessDeniedException(AccessDeniedException ex) {
        ErrorResponse errorResponse = new ErrorResponse(
            HttpStatus.FORBIDDEN.value(),
            "접근 권한이 없습니다.",
            LocalDateTime.now()
        );
        return new ResponseEntity<>(errorResponse, HttpStatus.FORBIDDEN);
    }
}
```

## 테스트 시나리오

### 1. 인증 테스트
```java
@Test
public void testUserRegistrationAndLogin() {
    // 1. 회원가입
    SignUpRequest signUpRequest = new SignUpRequest("testuser", "test@email.com", "Test@1234");
    ResponseEntity<?> signUpResponse = authController.registerUser(signUpRequest);
    assertEquals(HttpStatus.OK, signUpResponse.getStatusCode());
    
    // 2. 로그인
    LoginRequest loginRequest = new LoginRequest("testuser", "Test@1234");
    ResponseEntity<?> loginResponse = authController.authenticateUser(loginRequest);
    assertEquals(HttpStatus.OK, loginResponse.getStatusCode());
    
    // 3. JWT 토큰 확인
    JwtResponse jwtResponse = (JwtResponse) loginResponse.getBody();
    assertNotNull(jwtResponse.getAccessToken());
}
```

### 2. 권한 테스트
```java
@Test
@WithMockUser(roles = "USER")
public void testUserAccessToUserEndpoint() {
    mockMvc.perform(get("/api/user/profile"))
        .andExpect(status().isOk());
}

@Test
@WithMockUser(roles = "USER")
public void testUserAccessToAdminEndpoint() {
    mockMvc.perform(get("/api/admin/users"))
        .andExpect(status().isForbidden());
}
```

## 학습 포인트

1. **JWT의 Stateless 특성**
    - 서버에 세션을 저장하지 않음
    - 수평적 확장이 용이
    - 토큰 자체에 정보 포함

2. **RBAC의 유연성**
    - 역할과 권한의 분리
    - 동적 권한 부여 가능
    - 세밀한 접근 제어

3. **BCrypt의 보안성**
    - Salt 자동 생성
    - 단방향 암호화
    - 연산 비용 조절 가능

## 추가 구현 가능한 기능

1. **Refresh Token**
    - Access Token 만료 시 자동 갱신
    - Refresh Token Rotation

2. **OAuth2 통합**
    - 소셜 로그인 (Google, GitHub)
    - OAuth2 Resource Server

3. **2단계 인증**
    - TOTP 기반 2FA
    - SMS 인증

4. **감사 로그**
    - 로그인 이력
    - 권한 변경 이력
    - 보안 이벤트 추적