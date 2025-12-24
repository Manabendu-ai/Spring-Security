# 🔐 Spring Security - Complete Guide

![Spring Security](https://img.shields.io/badge/Spring%20Security-6DB33F?style=for-the-badge&logo=spring-security&logoColor=white)
![Java](https://img.shields.io/badge/Java-ED8B00?style=for-the-badge&logo=openjdk&logoColor=white)
![Spring Boot](https://img.shields.io/badge/Spring%20Boot-6DB33F?style=for-the-badge&logo=spring-boot&logoColor=white)

## 📚 Table of Contents

- [Introduction](#-introduction)
- [Core Concepts](#-core-concepts)
- [Authentication](#-authentication)
- [Authorization](#-authorization)
- [Security Configuration](#️-security-configuration)
- [Password Encoding](#-password-encoding)
- [JWT Authentication](#-jwt-authentication)
- [OAuth2 & Social Login](#-oauth2--social-login)
- [Method Security](#-method-security)
- [CSRF Protection](#️-csrf-protection)
- [CORS Configuration](#-cors-configuration)
- [Session Management](#-session-management)
- [Common Security Headers](#-common-security-headers)
- [Best Practices](#-best-practices)

---

## 🎯 Introduction

**Spring Security** is a powerful and highly customizable authentication and access-control framework for Java applications. It is the de-facto standard for securing Spring-based applications.

### ✨ Key Features

- 🔑 Comprehensive authentication support
- 🛡️ Authorization mechanisms
- 🚫 Protection against common attacks (CSRF, Session Fixation, Clickjacking)
- 🔐 Password encoding and encryption
- 🌐 OAuth2 and OpenID Connect support
- 🎫 JWT token-based authentication
- 📱 Remember-me authentication
- 🔄 Session management

---

## 🧩 Core Concepts

### 🔍 Security Filter Chain

Spring Security uses a chain of filters to intercept requests and apply security rules.

```
HTTP Request → Filter Chain → Controller
```

**Key Filters:**
- `UsernamePasswordAuthenticationFilter` - Processes login requests
- `BasicAuthenticationFilter` - HTTP Basic authentication
- `BearerTokenAuthenticationFilter` - JWT token validation
- `CsrfFilter` - CSRF protection
- `ExceptionTranslationFilter` - Handles security exceptions

### 👤 Principal

Represents the currently authenticated user. Contains user details and authorities.

### 🎭 Authentication

An interface representing an authentication request or authenticated principal.

```java
Authentication auth = SecurityContextHolder.getContext().getAuthentication();
String username = auth.getName();
```

### 🏛️ SecurityContext

Holds the security information of the current thread of execution, including details about the principal.

### 🗄️ SecurityContextHolder

Provides access to the `SecurityContext`. Strategies include:
- `MODE_THREADLOCAL` (default) - Each thread has its own security context
- `MODE_INHERITABLETHREADLOCAL` - Child threads inherit security context
- `MODE_GLOBAL` - All threads share the same security context

---

## 🔑 Authentication

### 📝 Basic Authentication Flow

1. User submits credentials (username/password)
2. `AuthenticationManager` delegates to `AuthenticationProvider`
3. `UserDetailsService` loads user from database
4. `PasswordEncoder` verifies password
5. `Authentication` object is created and stored in `SecurityContext`

### 🏗️ Key Components

#### AuthenticationManager
Central interface for authentication. Usually implemented by `ProviderManager`.

```java
@Bean
public AuthenticationManager authenticationManager(AuthenticationConfiguration config) 
    throws Exception {
    return config.getAuthenticationManager();
}
```

#### AuthenticationProvider
Performs specific authentication type.

```java
@Bean
public AuthenticationProvider authenticationProvider() {
    DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
    provider.setUserDetailsService(userDetailsService);
    provider.setPasswordEncoder(passwordEncoder());
    return provider;
}
```

#### UserDetailsService
Loads user-specific data during authentication.

```java
@Service
public class CustomUserDetailsService implements UserDetailsService {
    @Override
    public UserDetails loadUserByUsername(String username) 
        throws UsernameNotFoundException {
        // Load user from database
        return User.builder()
            .username(user.getUsername())
            .password(user.getPassword())
            .roles(user.getRoles())
            .build();
    }
}
```

#### UserDetails
Provides core user information.

```java
public interface UserDetails {
    Collection<? extends GrantedAuthority> getAuthorities();
    String getPassword();
    String getUsername();
    boolean isAccountNonExpired();
    boolean isAccountNonLocked();
    boolean isCredentialsNonExpired();
    boolean isEnabled();
}
```

---

## 🛡️ Authorization

### 🎫 Authorities vs Roles

**Authority:** A fine-grained permission (e.g., `READ_PRIVILEGE`, `WRITE_PRIVILEGE`)

**Role:** A collection of authorities (e.g., `ROLE_USER`, `ROLE_ADMIN`)

```java
// Authority
.hasAuthority("READ_PRIVILEGE")

// Role (automatically prefixes with ROLE_)
.hasRole("ADMIN") // equals hasAuthority("ROLE_ADMIN")
```

### 🔒 Access Control

```java
http.authorizeHttpRequests(auth -> auth
    .requestMatchers("/public/**").permitAll()
    .requestMatchers("/admin/**").hasRole("ADMIN")
    .requestMatchers("/user/**").hasAnyRole("USER", "ADMIN")
    .requestMatchers("/api/**").hasAuthority("API_ACCESS")
    .anyRequest().authenticated()
);
```

### 📊 Authorization Expressions

| Expression | Description |
|------------|-------------|
| `permitAll()` | Allow access to everyone |
| `denyAll()` | Deny access to everyone |
| `authenticated()` | Require authentication |
| `hasRole("ADMIN")` | Require specific role |
| `hasAnyRole("USER","ADMIN")` | Require any of the roles |
| `hasAuthority("READ")` | Require specific authority |
| `hasAnyAuthority("READ","WRITE")` | Require any of the authorities |

---

## ⚙️ Security Configuration

### 🔧 Spring Security 6+ Configuration

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) 
        throws Exception {
        http
            .csrf(csrf -> csrf.disable())
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/auth/**").permitAll()
                .requestMatchers("/api/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated()
            )
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            )
            .authenticationProvider(authenticationProvider())
            .addFilterBefore(jwtAuthFilter, 
                UsernamePasswordAuthenticationFilter.class);
        
        return http.build();
    }
}
```

### 🔐 Multiple Security Configurations

```java
@Configuration
@EnableWebSecurity
public class MultiSecurityConfig {

    @Bean
    @Order(1)
    public SecurityFilterChain apiSecurityFilterChain(HttpSecurity http) 
        throws Exception {
        http
            .securityMatcher("/api/**")
            .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
            .oauth2ResourceServer(oauth2 -> oauth2.jwt());
        return http.build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain webSecurityFilterChain(HttpSecurity http) 
        throws Exception {
        http
            .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
            .formLogin(Customizer.withDefaults());
        return http.build();
    }
}
```

---

## 🔒 Password Encoding

### 🛡️ Why Encode Passwords?

Never store passwords in plain text! Use strong one-way hashing algorithms.

### 📦 Common Password Encoders

```java
@Bean
public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder(); // Recommended
}
```

**Available Encoders:**
- `BCryptPasswordEncoder` ✅ (Recommended - adaptive and secure)
- `Argon2PasswordEncoder` ✅ (Most secure, memory-hard)
- `Pbkdf2PasswordEncoder` ✅ (NIST recommended)
- `SCryptPasswordEncoder` ✅ (Memory-intensive)
- `NoOpPasswordEncoder` ❌ (Only for testing!)

### 🔄 Password Encoding Example

```java
@Service
public class UserService {
    
    @Autowired
    private PasswordEncoder passwordEncoder;
    
    public void registerUser(String username, String rawPassword) {
        String encodedPassword = passwordEncoder.encode(rawPassword);
        // Save user with encoded password
    }
    
    public boolean verifyPassword(String rawPassword, String encodedPassword) {
        return passwordEncoder.matches(rawPassword, encodedPassword);
    }
}
```

### 🔀 DelegatingPasswordEncoder

Supports multiple encoding formats with identifier prefix.

```java
@Bean
public PasswordEncoder passwordEncoder() {
    return PasswordEncoderFactories.createDelegatingPasswordEncoder();
}
```

Format: `{bcrypt}$2a$10$...`, `{pbkdf2}...`

---

## 🎫 JWT Authentication

### 📖 What is JWT?

**JSON Web Token** - A compact, URL-safe token format for securely transmitting information between parties.

Structure: `header.payload.signature`

### 🏗️ JWT Implementation

#### 1️⃣ Add Dependencies

```xml
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt-api</artifactId>
    <version>0.11.5</version>
</dependency>
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt-impl</artifactId>
    <version>0.11.5</version>
</dependency>
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt-jackson</artifactId>
    <version>0.11.5</version>
</dependency>
```

#### 2️⃣ JWT Service

```java
@Service
public class JwtService {
    
    @Value("${jwt.secret}")
    private String SECRET_KEY;
    
    public String generateToken(UserDetails userDetails) {
        return Jwts.builder()
            .setSubject(userDetails.getUsername())
            .setIssuedAt(new Date())
            .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 10))
            .signWith(getSigningKey(), SignatureAlgorithm.HS256)
            .compact();
    }
    
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }
    
    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }
    
    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }
    
    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }
    
    private <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }
    
    private Claims extractAllClaims(String token) {
        return Jwts.parserBuilder()
            .setSigningKey(getSigningKey())
            .build()
            .parseClaimsJws(token)
            .getBody();
    }
    
    private Key getSigningKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
```

#### 3️⃣ JWT Authentication Filter

```java
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    
    @Autowired
    private JwtService jwtService;
    
    @Autowired
    private UserDetailsService userDetailsService;
    
    @Override
    protected void doFilterInternal(
        HttpServletRequest request,
        HttpServletResponse response,
        FilterChain filterChain
    ) throws ServletException, IOException {
        
        final String authHeader = request.getHeader("Authorization");
        final String jwt;
        final String username;
        
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }
        
        jwt = authHeader.substring(7);
        username = jwtService.extractUsername(jwt);
        
        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = userDetailsService.loadUserByUsername(username);
            
            if (jwtService.isTokenValid(jwt, userDetails)) {
                UsernamePasswordAuthenticationToken authToken = 
                    new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        userDetails.getAuthorities()
                    );
                authToken.setDetails(
                    new WebAuthenticationDetailsSource().buildDetails(request)
                );
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }
        filterChain.doFilter(request, response);
    }
}
```

#### 4️⃣ Authentication Controller

```java
@RestController
@RequestMapping("/api/auth")
public class AuthController {
    
    @Autowired
    private AuthenticationManager authenticationManager;
    
    @Autowired
    private JwtService jwtService;
    
    @Autowired
    private UserDetailsService userDetailsService;
    
    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@RequestBody AuthRequest request) {
        authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken(
                request.getUsername(),
                request.getPassword()
            )
        );
        
        UserDetails userDetails = userDetailsService.loadUserByUsername(request.getUsername());
        String token = jwtService.generateToken(userDetails);
        
        return ResponseEntity.ok(new AuthResponse(token));
    }
}
```

---

## 🌐 OAuth2 & Social Login

### 🎨 What is OAuth2?

An authorization framework that enables applications to obtain limited access to user accounts on HTTP services.

### 🔑 OAuth2 Flow

1. User clicks "Login with Google/GitHub/Facebook"
2. Redirected to OAuth2 provider
3. User grants permissions
4. Provider redirects back with authorization code
5. Application exchanges code for access token
6. Application uses token to access user info

### ⚙️ Configuration

```yaml
spring:
  security:
    oauth2:
      client:
        registration:
          google:
            client-id: ${GOOGLE_CLIENT_ID}
            client-secret: ${GOOGLE_CLIENT_SECRET}
            scope:
              - email
              - profile
          github:
            client-id: ${GITHUB_CLIENT_ID}
            client-secret: ${GITHUB_CLIENT_SECRET}
            scope:
              - user:email
              - read:user
```

### 🏗️ OAuth2 Security Config

```java
@Configuration
@EnableWebSecurity
public class OAuth2SecurityConfig {
    
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/", "/login", "/error").permitAll()
                .anyRequest().authenticated()
            )
            .oauth2Login(oauth2 -> oauth2
                .loginPage("/login")
                .defaultSuccessUrl("/dashboard", true)
                .failureUrl("/login?error=true")
                .userInfoEndpoint(userInfo -> userInfo
                    .userService(customOAuth2UserService)
                )
            );
        
        return http.build();
    }
}
```

### 👤 Custom OAuth2 User Service

```java
@Service
public class CustomOAuth2UserService extends DefaultOAuth2UserService {
    
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oauth2User = super.loadUser(userRequest);
        
        // Process OAuth2 user data
        String email = oauth2User.getAttribute("email");
        String name = oauth2User.getAttribute("name");
        
        // Save or update user in database
        
        return oauth2User;
    }
}
```

---

## 🎯 Method Security

### 🔓 Enable Method Security

```java
@Configuration
@EnableMethodSecurity(
    prePostEnabled = true,
    securedEnabled = true,
    jsr250Enabled = true
)
public class MethodSecurityConfig {
}
```

### 🛡️ Security Annotations

#### @PreAuthorize
Checks authorization before method execution.

```java
@PreAuthorize("hasRole('ADMIN')")
public void deleteUser(Long id) {
    // Only admins can execute
}

@PreAuthorize("hasAuthority('WRITE_PRIVILEGE')")
public void updateResource() {
    // Requires WRITE_PRIVILEGE
}

@PreAuthorize("#username == authentication.principal.username")
public void updateProfile(String username) {
    // Users can only update their own profile
}
```

#### @PostAuthorize
Checks authorization after method execution.

```java
@PostAuthorize("returnObject.owner == authentication.name")
public Document getDocument(Long id) {
    // Verify user owns the document after retrieval
    return documentRepository.findById(id);
}
```

#### @Secured
Simple role-based authorization.

```java
@Secured("ROLE_ADMIN")
public void adminOperation() {
    // Only admins
}

@Secured({"ROLE_USER", "ROLE_ADMIN"})
public void userOperation() {
    // Users or admins
}
```

#### @RolesAllowed (JSR-250)

```java
@RolesAllowed("ADMIN")
public void deleteAllUsers() {
    // Admin only
}
```

### 🔍 SpEL Expressions

Common Spring Expression Language patterns:

```java
@PreAuthorize("hasRole('ADMIN')")
@PreAuthorize("hasAnyRole('USER', 'ADMIN')")
@PreAuthorize("hasAuthority('READ_PRIVILEGE')")
@PreAuthorize("#id == authentication.principal.id")
@PreAuthorize("@userSecurity.canAccessUser(#id)")
@PreAuthorize("hasPermission(#contact, 'admin')")
```

---

## 🛡️ CSRF Protection

### 🤔 What is CSRF?

**Cross-Site Request Forgery** - An attack that forces users to execute unwanted actions on a web application where they're authenticated.

### 🔒 CSRF Protection Strategies

#### 1️⃣ Enable CSRF (Default for form-based apps)

```java
http.csrf(csrf -> csrf
    .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
);
```

#### 2️⃣ Disable CSRF (For stateless REST APIs)

```java
http.csrf(csrf -> csrf.disable());
```

#### 3️⃣ Selective CSRF Protection

```java
http.csrf(csrf -> csrf
    .ignoringRequestMatchers("/api/**")
);
```

### 📝 Using CSRF Token in Forms

```html
<form method="post" action="/transfer">
    <input type="hidden" name="${_csrf.parameterName}" value="${_csrf.token}"/>
    <!-- form fields -->
</form>
```

### 📡 CSRF Token in AJAX

```javascript
const token = document.querySelector('meta[name="_csrf"]').content;
const header = document.querySelector('meta[name="_csrf_header"]').content;

fetch('/api/data', {
    method: 'POST',
    headers: {
        [header]: token,
        'Content-Type': 'application/json'
    },
    body: JSON.stringify(data)
});
```

---

## 🌍 CORS Configuration

### 🤔 What is CORS?

**Cross-Origin Resource Sharing** - A mechanism that allows restricted resources on a web page to be requested from another domain.

### ⚙️ CORS Configuration

#### 1️⃣ Global CORS Configuration

```java
@Configuration
public class CorsConfig {
    
    @Bean
    public WebMvcConfigurer corsConfigurer() {
        return new WebMvcConfigurer() {
            @Override
            public void addCorsMappings(CorsRegistry registry) {
                registry.addMapping("/api/**")
                    .allowedOrigins("http://localhost:3000", "https://myapp.com")
                    .allowedMethods("GET", "POST", "PUT", "DELETE", "OPTIONS")
                    .allowedHeaders("*")
                    .allowCredentials(true)
                    .maxAge(3600);
            }
        };
    }
}
```

#### 2️⃣ Security CORS Configuration

```java
http.cors(cors -> cors
    .configurationSource(request -> {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(Arrays.asList("http://localhost:3000"));
        config.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE"));
        config.setAllowedHeaders(Arrays.asList("*"));
        config.setAllowCredentials(true);
        return config;
    })
);
```

#### 3️⃣ Controller-Level CORS

```java
@RestController
@CrossOrigin(origins = "http://localhost:3000")
public class ApiController {
    
    @CrossOrigin(origins = "https://trusted-site.com")
    @GetMapping("/data")
    public List<Data> getData() {
        return dataService.getAll();
    }
}
```

---

## 🔄 Session Management

### 📊 Session Creation Policies

```java
http.sessionManagement(session -> session
    .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
);
```

**Policies:**
- `ALWAYS` - Always create a session
- `IF_REQUIRED` - Create session only if required (default)
- `NEVER` - Never create session, but use one if it exists
- `STATELESS` - No session will be created or used (for JWT/OAuth2)

### 🔐 Concurrent Session Control

```java
http.sessionManagement(session -> session
    .maximumSessions(1)
    .maxSessionsPreventsLogin(true)
    .expiredUrl("/session-expired")
);
```

### 🚫 Session Fixation Protection

```java
http.sessionManagement(session -> session
    .sessionFixation().migrateSession()
);
```

**Strategies:**
- `none()` - No protection (not recommended)
- `newSession()` - Create new session, don't copy attributes
- `migrateSession()` - Create new session, copy attributes (default)
- `changeSessionId()` - Use existing session, change ID

### ⏱️ Session Timeout Configuration

```yaml
server:
  servlet:
    session:
      timeout: 30m  # 30 minutes
```

---

## 🔒 Common Security Headers

### 🛡️ Security Headers Configuration

```java
http.headers(headers -> headers
    .contentSecurityPolicy(csp -> csp
        .policyDirectives("default-src 'self'")
    )
    .frameOptions(frame -> frame.deny())
    .xssProtection(xss -> xss.enable())
    .contentTypeOptions(Customizer.withDefaults())
    .referrerPolicy(referrer -> referrer
        .policy(ReferrerPolicyHeaderWriter.ReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN)
    )
    .permissionsPolicy(permissions -> permissions
        .policy("geolocation=(self)")
    )
);
```

### 📋 Important Security Headers

| Header | Description | Example |
|--------|-------------|---------|
| **Content-Security-Policy** | Controls resources the browser can load | `default-src 'self'` |
| **X-Frame-Options** | Prevents clickjacking | `DENY` or `SAMEORIGIN` |
| **X-Content-Type-Options** | Prevents MIME sniffing | `nosniff` |
| **X-XSS-Protection** | Enables XSS filter | `1; mode=block` |
| **Strict-Transport-Security** | Forces HTTPS | `max-age=31536000` |
| **Referrer-Policy** | Controls referrer information | `strict-origin-when-cross-origin` |
| **Permissions-Policy** | Controls browser features | `geolocation=(self)` |

---

## ✅ Best Practices

### 🎯 General Security

- ✅ Always use HTTPS in production
- ✅ Implement proper password policies (minimum length, complexity)
- ✅ Use strong password encoding (BCrypt, Argon2)
- ✅ Implement rate limiting to prevent brute force attacks
- ✅ Log security events (failed logins, access denials)
- ✅ Keep dependencies updated (Spring Security, libraries)
- ✅ Use security headers (CSP, X-Frame-Options, etc.)
- ✅ Implement proper session timeout
- ✅ Validate and sanitize all user inputs
- ✅ Use parameterized queries to prevent SQL injection

### 🔐 Authentication & Authorization

- ✅ Use JWT for stateless APIs
- ✅ Implement refresh token mechanism
- ✅ Store sensitive data (JWT secret) in environment variables
- ✅ Use fine-grained authorities instead of just roles
- ✅ Implement multi-factor authentication (MFA) for sensitive operations
- ✅ Use OAuth2 for third-party integrations
- ✅ Implement account lockout after failed login attempts
- ✅ Send email notifications for suspicious activities

### 🛡️ API Security

- ✅ Disable CSRF for stateless REST APIs
- ✅ Implement proper CORS configuration
- ✅ Use API versioning (`/api/v1/...`)
- ✅ Implement request/response encryption for sensitive data
- ✅ Use API keys or OAuth2 for public APIs
- ✅ Implement request throttling and rate limiting
- ✅ Document security requirements in API documentation
- ✅ Validate Content-Type and Accept headers

### 📊 Monitoring & Maintenance

- ✅ Monitor authentication failures and anomalies
- ✅ Implement security auditing and logging
- ✅ Regular security audits and penetration testing
- ✅ Keep track of security vulnerabilities (CVEs)
- ✅ Implement automated security scanning in CI/CD
- ✅ Have an incident response plan
- ✅ Regular backup of security configurations

### ❌ What NOT to Do

- ❌ Never store passwords in plain text
- ❌ Never expose sensitive information in error messages
- ❌ Never trust user input without validation
- ❌ Never commit secrets to version control
- ❌ Never use default credentials
- ❌ Never disable security features without understanding implications
- ❌ Never log sensitive information (passwords, tokens)
- ❌ Never use weak encryption algorithms (MD5, SHA1)

---

## 📚 Additional Resources

### 📖 Official Documentation
- [Spring Security Reference](https://docs.spring.io/spring-security/reference/)
- [Spring Security API Docs](https://docs.spring.io/spring-security/site/docs/current/api/)

### 🎓 Tutorials & Guides
- [Baeldung Spring Security](https://www.baeldung.com/security-spring)
- [Spring Security Architecture](https://spring.io/guides/topicals/spring-security-architecture)

### 🔧 Tools
- [JWT Debugger](https://jwt.io/)
- [OWASP ZAP](https://www.zaproxy.org/)
- [Burp Suite](https://portswigger.net/burp)

### 📦 Related Projects
- [Spring Authorization Server](https://github.com/spring-projects/spring-authorization-server)
- [Spring Cloud Security](https://spring.io/projects/spring-cloud-security)

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📄 License

This documentation is provided under the MIT License.

---

**Made with ❤️ by the Spring Security Community**

![Spring](https://img.shields.io/badge/Spring-6DB33F?style=for-the-badge&logo=spring&logoColor=white)
![Security](https://img.shields.io/badge/Security-FF0000?style=for-the-badge&logo=security&logoColor=white)
