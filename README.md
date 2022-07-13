## Spring Boot Signup & Login with JWT Authentication Flow
Sơ đồ hiển thị cách thực hiện việc đăng ký, đăng nhập và ủy quyền như thế nào.
![Spring boot sigup & signin with Jwt Auth Flow](https://bezkoder.com/wp-content/uploads/2019/10/spring-boot-authentication-jwt-spring-security-flow.png)

Một Jwt hợp lệ phải được thêm vào HTTP Authorization Header nếu người dùng muốn truy cập các tài nguyên được security được bảo vệ.
Bạn sẽ cần thực hiện việc refresh token.
![Spring boot refresh token](https://www.bezkoder.com/wp-content/uploads/2021/04/spring-boot-refresh-token-jwt-example-flow.png)

## Spring Boot Server Architecture with Spring Security
Bạn có thể có một cái nhìn tổng quan về Spring Boot Server với sơ dồ bên dưới.
![Spring boot server Architecture with Spring Security](https://www.bezkoder.com/wp-content/uploads/2019/10/spring-boot-authentication-spring-security-architecture.png)

### Spring Security
- **WebSecurityConfigurerAdapter** là mấu chốt của việc triển khai bảo mật. Nó cung cấp các HttpSecurity configurations để cấu hình cors, csrf, session management(quản lý phiên), rules cho các tài nguyên được bảo mật. Ta có thể mở rộng và tùy chỉnh cấu hình mặc định bao gồm các thành phân dưới đây.

- **UserDetailsService** interface có một phương thức để load người dùng theo tên và trả về đối tượng UserDetails mà Spring Security có thể sử dụng để authentication và validation.

- **UserDetails** chứa thông tin cần thiết (như: username. password, atuhorities) để xây dựng  một Authentication object.

- **UsernamePassWordAuthenticationToken** gets{username, password} từ login request, AuthenticationManager sẽ sử dụng nó để xác thực tài khoản đăng nhập.

- **AuthenticationManager** có DaoAuthenticationProvider (với sự trợ giúp của UserDetailsService và PasswordEncoder) để xác thực UsernamePasswordAuthenticationToken object. Nếu thành công, AuthenticationManager trả về một fully populated Authentication object(bao gồm các authorities được cấp).

- **OncePerRequestFilter** thực hiện cho mỗi yêu cầu của API. Nó cung cấp phương thức doFilterInternal() để triển khai phân tích và xác thực Jwt, loading User details (sử dụng UserDetailsService), kiển tra Authorization(sử dụng UsernamePasswordAuthenticationToken).

-  **AuthenticationEntryPoint** will catch authentication error.

**Repository** bao gồm UserRepository và RoleRepository để làm việc với DB, và import và trong Controller.
**Controller** nhận và xử lý yêu cầu sau khi nó được lọc bởi OncePerRequestFilter.
– AuthController xử lý signup/login requests
– TestController truy cập các phương thức và tài nguyên được bảo vệ với vai trò đã được xác nhận.

##
# Project Structure
![Project Structure](https://www.bezkoder.com/wp-content/uploads/2019/10/spring-boot-authentication-spring-security-project-structure.png)

**security pakage** cấu hình và triển khai security object ở đây.
- WebSecurityConfig extends WebSecurityConfigurerAdapter
- UserDetailsServiceImpl implements UserDetailsService
- UserDetailsImpl implements UserDetails
- AuthEntryPointJwt implements AuthenticationEntryPoint
- AuthTokenFilter extends OncePerRequestFilter
- JwtUtils cung cấp phương thức cho generating, parsing, validating JWT

**controllers** xử lý signup/signin requests và authorized requests.
- AuthController: @PostMapping('/signin'), @PostMapping('/signup')
- TestController: @GetMapping(‘/api/test/all’), @GetMapping(‘/api/test/[role]’)

**repository** có các interface extend từ Spring Data JpaRepository để tương tác với DB.
- UserRepository extends JpaRepository<User, Long>
- RoleRepository extends JpaRepository<Role, Long>

**models** defines two main models for Authentication (User) & Authorization (Role). They have many-to-many relationship.

**payload** defines classes for Request and Response objects

### Setup new Spring Boot project

The pom.xml file add these dependencies

```
<dependency>
	<groupId>org.springframework.boot</groupId>
	<artifactId>spring-boot-starter-data-jpa</artifactId>
</dependency>
<dependency>
	<groupId>org.springframework.boot</groupId>
	<artifactId>spring-boot-starter-security</artifactId>
</dependency>
<dependency>
	<groupId>org.springframework.boot</groupId>
	<artifactId>spring-boot-starter-web</artifactId>
</dependency>
<dependency>
	<groupId>io.jsonwebtoken</groupId>
	<artifactId>jjwt</artifactId>
	<version>0.9.1</version>
</dependency>
```

We alse need to add one more dependencies.
- If you want to use postgresql
```
<dependency>
	<groupId>org.postgresql</groupId>
	<artifactId>postgresql</artifactId>
	<scope>runtime</scope>
</dependency>
```
- or MySql
```
<dependency>
	<groupId>mysql</groupId>
	<artifactId>mysql-connector-java</artifactId>
	<scope>runtime</scope>
</dependency>
```

### Configure Spring Datasource, JPA, App properties
For PostgreSql
```
spring.datasource.url= jdbc:postgresql://localhost:5432/testdb
spring.datasource.username= postgres
spring.datasource.password= 123
spring.jpa.properties.hibernate.jdbc.lob.non_contextual_creation= true
spring.jpa.properties.hibernate.dialect= org.hibernate.dialect.PostgreSQLDialect
# Hibernate ddl auto (create, create-drop, validate, update)
spring.jpa.hibernate.ddl-auto= update
# App Properties
pc.app.jwtSecret= bezKoderSecretKey
pc.app.jwtExpirationMs= 86400000
```

For MySql
```
spring.datasource.url= jdbc:mysql://localhost:3306/testdb?useSSL=false
spring.datasource.username= root
spring.datasource.password= 123456
spring.jpa.properties.hibernate.dialect= org.hibernate.dialect.MySQL5InnoDBDialect
spring.jpa.hibernate.ddl-auto= update
# App Properties
pc.app.jwtSecret= bezKoderSecretKey
pc.app.jwtExpirationMs= 86400000
```

### Create the models

Tôi sẽ có 3 bảng in DB: users, roles and user_roles với quan hệ many-to-many.
In model pakage, create 3 files:

ERole.java
```
public enum ERole {
	ROLE_USER,
    ROLE_MODERATOR,
    ROLE_ADMIN
}
```
Role.java
```
import javax.persistence.*;
@Entity
@Table(name = "roles")
public class Role {
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Integer id;
	@Enumerated(EnumType.STRING)
	@Column(length = 20)
	private ERole name;
	public Role() {
	}
	public Role(ERole name) {
		this.name = name;
	}
	public Integer getId() {
		return id;
	}
	public void setId(Integer id) {
		this.id = id;
	}
	public ERole getName() {
		return name;
	}
	public void setName(ERole name) {
		this.name = name;
	}
}
```

User.java
```
import java.util.HashSet;
import java.util.Set;
import javax.persistence.*;
import javax.validation.constraints.Email;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Size;
@Entity
@Table(	name = "users", 
		uniqueConstraints = { 
			@UniqueConstraint(columnNames = "username"),
			@UniqueConstraint(columnNames = "email") 
		})
public class User {
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;
	@NotBlank
	@Size(max = 20)
	private String username;
	@NotBlank
	@Size(max = 50)
	@Email
	private String email;
	@NotBlank
	@Size(max = 120)
	private String password;
	@ManyToMany(fetch = FetchType.LAZY)
	@JoinTable(	name = "user_roles", 
				joinColumns = @JoinColumn(name = "user_id"), 
				inverseJoinColumns = @JoinColumn(name = "role_id"))
	private Set<Role> roles = new HashSet<>();
	public User() {
	}
	public User(String username, String email, String password) {
		this.username = username;
		this.email = email;
		this.password = password;
	}
	public Long getId() {
		return id;
	}
	public void setId(Long id) {
		this.id = id;
	}
	public String getUsername() {
		return username;
	}
	public void setUsername(String username) {
		this.username = username;
	}
	public String getEmail() {
		return email;
	}
	public void setEmail(String email) {
		this.email = email;
	}
	public String getPassword() {
		return password;
	}
	public void setPassword(String password) {
		this.password = password;
	}
	public Set<Role> getRoles() {
		return roles;
	}
	public void setRoles(Set<Role> roles) {
		this.roles = roles;
	}
}
```
### Inplement Repositories

**UserRepository**
```
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import com.bezkoder.springjwt.models.User;
@Repository
public interface UserRepository extends JpaRepository<User, Long> {
	Optional<User> findByUsername(String username);
	Boolean existsByUsername(String username);
	Boolean existsByEmail(String email);
}
```

**RoleRepository**
```
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import com.bezkoder.springjwt.models.ERole;
import com.bezkoder.springjwt.models.Role;
@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {
	Optional<Role> findByName(ERole name);
}
```

### Configure Spring Security
In security package, create WebSecurityConfig class that extends WebSecurityConfigurerAdapter.

WebSecurityConfig.java
```
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import com.bezkoder.springjwt.security.jwt.AuthEntryPointJwt;
import com.bezkoder.springjwt.security.jwt.AuthTokenFilter;
import com.bezkoder.springjwt.security.services.UserDetailsServiceImpl;
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(
		// securedEnabled = true,
		// jsr250Enabled = true,
		prePostEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
	@Autowired
	UserDetailsServiceImpl userDetailsService;
	@Autowired
	private AuthEntryPointJwt unauthorizedHandler;
	@Bean
	public AuthTokenFilter authenticationJwtTokenFilter() {
		return new AuthTokenFilter();
	}
	@Override
	public void configure(AuthenticationManagerBuilder authenticationManagerBuilder) throws Exception {
		authenticationManagerBuilder.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder());
	}
	@Bean
	@Override
	public AuthenticationManager authenticationManagerBean() throws Exception {
		return super.authenticationManagerBean();
	}
	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.cors().and().csrf().disable()
			.exceptionHandling().authenticationEntryPoint(unauthorizedHandler).and()
			.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
			.authorizeRequests().antMatchers("/api/auth/**").permitAll()
			.antMatchers("/api/test/**").permitAll()
			.anyRequest().authenticated();
		http.addFilterBefore(authenticationJwtTokenFilter(), UsernamePasswordAuthenticationFilter.class);
	}
}
```

- **@EnableWebSecurity** cho phép spring tìm và tự động áp dụng class vào The global Web Security.
- **@EnableGlobalMethodSecurity** cung cấp AOP security trên các phương thức. Nó enable @PreAuthorize và @PostAuthorize, Nó cũng hỗ trợ JSR-250. Bạn có thể tìm thấy nhiều tham số hơn trong cấu hình Method Security Expressions. 
- Tôi ghi đè phương thức cấu hình (HttpSecurity http) từ WebSecurityConfigerAdapter interface. Nó cho Spring Security biết cách tôi cấu hình cors và csrf, khi tôi muốn yêu cầu tất cả người dùng được xác thực hay không, Bộ filter nào (AuthTokenFilter), khi tôi muốn nó hoạt động (filter before UsernamePasswordAuthenticationFilter) và Exception Handler nào được chọn(AuthEntryPointJwt).
- Spring Security sẽ load chi tiết người dùng để thực hiện authentication & authorization. Vì vậy, nó có UserDetailSService interface thứ tôi cần để thực hiện.
-Việc triển khai UserDetailSService sẽ được sử dụng để cấu hình DaoAuthenticationProvider bằng phương thức AuthenticationManagerBuilder.userDetailsService().
- tôi cũng cần một PasswordEncoder cho DaoAuthenticationProvider. Nếu tôi không chỉ định, nó sẽ sử dụng văn bản thuần túy.

### Implement UserDetails & UserDetailsService
Nếu quá trình xác thực thành công, tôi có thể lấy được thông tin của người dùng như username, password, authorities từ Authentication object.
```
Authentication authentication = 
        authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken(username, password)
        );
UserDetails userDetails = (UserDetails) authentication.getPrincipal();
// userDetails.getUsername()
// userDetails.getPassword()
// userDetails.getAuthorities()
```

Nếu muốn lấy thêm dữ liệu (ID, email,...)có thể tạo một implement UserDetails interface này.
```
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import com.bezkoder.springjwt.models.User;
import com.fasterxml.jackson.annotation.JsonIgnore;
public class UserDetailsImpl implements UserDetails {
	private static final long serialVersionUID = 1L;
	private Long id;
	private String username;
	private String email;
	@JsonIgnore
	private String password;
	private Collection<? extends GrantedAuthority> authorities;
	public UserDetailsImpl(Long id, String username, String email, String password,
			Collection<? extends GrantedAuthority> authorities) {
		this.id = id;
		this.username = username;
		this.email = email;
		this.password = password;
		this.authorities = authorities;
	}
	public static UserDetailsImpl build(User user) {
		List<GrantedAuthority> authorities = user.getRoles().stream()
				.map(role -> new SimpleGrantedAuthority(role.getName().name()))
				.collect(Collectors.toList());
		return new UserDetailsImpl(
				user.getId(), 
				user.getUsername(), 
				user.getEmail(),
				user.getPassword(), 
				authorities);
	}
	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return authorities;
	}
	public Long getId() {
		return id;
	}
	public String getEmail() {
		return email;
	}
	@Override
	public String getPassword() {
		return password;
	}
	@Override
	public String getUsername() {
		return username;
	}
	@Override
	public boolean isAccountNonExpired() {
		return true;
	}
	@Override
	public boolean isAccountNonLocked() {
		return true;
	}
	@Override
	public boolean isCredentialsNonExpired() {
		return true;
	}
	@Override
	public boolean isEnabled() {
		return true;
	}
	@Override
	public boolean equals(Object o) {
		if (this == o)
			return true;
		if (o == null || getClass() != o.getClass())
			return false;
		UserDetailsImpl user = (UserDetailsImpl) o;
		return Objects.equals(id, user.id);
	}
}
```
Mã trên,có thể thấy tôi chuyển SET <ROLE> thành List<TrfedAdAuthority>. Nó rất quan trọng khi làm việc với Spring Security và Authentication Object sau này.

Tôi đã cần UserDetailsService để get UserDetails Object. Bạn có thể xem UserDetailsService interface chỉ có 1 phương thức:
```
public interface UserDetailsService {
    UserDetails loadUserByUsername(String username) throws UsernameNotFoundException;
}
```
Vì vậy, tôi implement và override phương thức LoadUserByUserName ().
security/services/UserDetailsServiceImpl.java
```
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import com.bezkoder.springjwt.models.User;
import com.bezkoder.springjwt.repository.UserRepository;
@Service
public class UserDetailsServiceImpl implements UserDetailsService {
	@Autowired
	UserRepository userRepository;
	@Override
	@Transactional
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		User user = userRepository.findByUsername(username)
				.orElseThrow(() -> new UsernameNotFoundException("User Not Found with username: " + username));
		return UserDetailsImpl.build(user);
	}
}
```
Trong mã trên, tôi get được toàn bộ User Object bằng cách sử dụng UserRepository, sau đó tôi build a UserDetails Object sử dụng phương thức static build()

### Filter the Requests
Let define một filter thực thi một lần cho mỗi yêu cầu. vì vậy, tôi tạo ra AuthTokenFilter class extends OncePerRequestFilter
và có 1 override doFilterInternal() phương thức.
security/jwt/AuthTokenFilter.java
```
import java.io.IOException;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import com.bezkoder.springjwt.security.services.UserDetailsServiceImpl;
public class AuthTokenFilter extends OncePerRequestFilter {
	@Autowired
	private JwtUtils jwtUtils;
	@Autowired
	private UserDetailsServiceImpl userDetailsService;
	private static final Logger logger = LoggerFactory.getLogger(AuthTokenFilter.class);
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		try {
			String jwt = parseJwt(request);
			if (jwt != null && jwtUtils.validateJwtToken(jwt)) {
				String username = jwtUtils.getUserNameFromJwtToken(jwt);
				UserDetails userDetails = userDetailsService.loadUserByUsername(username);
				UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
						userDetails, null, userDetails.getAuthorities());
				authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
				SecurityContextHolder.getContext().setAuthentication(authentication);
			}
		} catch (Exception e) {
			logger.error("Cannot set user authentication: {}", e);
		}
		filterChain.doFilter(request, response);
	}
	private String parseJwt(HttpServletRequest request) {
		String headerAuth = request.getHeader("Authorization");
		if (StringUtils.hasText(headerAuth) && headerAuth.startsWith("Bearer ")) {
			return headerAuth.substring(7, headerAuth.length());
		}
		return null;
	}
}
```

Vậy tôi đã làm những gì trong doFilterInternal():
- get Jwt từ Authorization header(cần loại bỏ Bearer ở đầu)
- nếu request có Jwt, validate và phân tích username từ nó
- từ username, get UserDetails để tạo ra 1 Authentication Object
- set the current UserDetails in SecurityContext using setAuthentication(authentication) method.

Sau đó, mỗi khi tôi muốn nhận userDetails, chỉ cần sử dụng SecurityContext như thế này:
```
UserDetails userDetails =
	(UserDetails) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
// userDetails.getUsername()
// userDetails.getPassword()
// userDetails.getAuthorities()
```
### Create JWT Utility class
This class has 3 function 
- tạo JWT từ username, date, expiration, secret
- get username từ JWT
- validate a JWT
security/jwt/JwtUtils.java
```
import java.util.Date;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import com.bezkoder.springjwt.security.services.UserDetailsImpl;
import io.jsonwebtoken.*;
@Component
public class JwtUtils {
	private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);
	@Value("${pc.app.jwtSecret}")
	private String jwtSecret;
	@Value("${pc.app.jwtExpirationMs}")
	private int jwtExpirationMs;
	public String generateJwtToken(Authentication authentication) {
		UserDetailsImpl userPrincipal = (UserDetailsImpl) authentication.getPrincipal();
		return Jwts.builder()
				.setSubject((userPrincipal.getUsername()))
				.setIssuedAt(new Date())
				.setExpiration(new Date((new Date()).getTime() + jwtExpirationMs))
				.signWith(SignatureAlgorithm.HS512, jwtSecret)
				.compact();
	}
	public String getUserNameFromJwtToken(String token) {
		return Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token).getBody().getSubject();
	}
	public boolean validateJwtToken(String authToken) {
		try {
			Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(authToken);
			return true;
		} catch (SignatureException e) {
			logger.error("Invalid JWT signature: {}", e.getMessage());
		} catch (MalformedJwtException e) {
			logger.error("Invalid JWT token: {}", e.getMessage());
		} catch (ExpiredJwtException e) {
			logger.error("JWT token is expired: {}", e.getMessage());
		} catch (UnsupportedJwtException e) {
			logger.error("JWT token is unsupported: {}", e.getMessage());
		} catch (IllegalArgumentException e) {
			logger.error("JWT claims string is empty: {}", e.getMessage());
		}
		return false;
	}
}
```
Nhớ rằng tôi đã thêm pc.app.jwtsecret và pc.app.jwtexpirationmss trong application.properies.

### Handle Authentication Exception
Giờ tôi tạo ra AuthEntryPointJwt class nó implement AuthenticationEntryPoint interface. Sau đó, tôi override commence() phương thức. Phương thức này sẽ được kich hoạt bất cứ lúc nào người dùng không được xác thực muốn truy cập tài nguyên được bảo vệ và AuthenticationExeption sẽ được ném ra.
security/jwt/AuthEntryPointJwt.java
```
import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;
@Component
public class AuthEntryPointJwt implements AuthenticationEntryPoint {
	private static final Logger logger = LoggerFactory.getLogger(AuthEntryPointJwt.class);
	@Override
	public void commence(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException authException) throws IOException, ServletException {
		logger.error("Unauthorized error: {}", authException.getMessage());
		response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Error: Unauthorized");
	}
}
```
HttpServletResponse.SC_UNAUTHORIZED là mã cho trạng thái code 401.

### Define payloads for Spring RestController
**Requests**:
- LoginRequest: { username, password }
- SignupRequest: { username, email, password }
**Responses**:
- JwtResponse: { token, type, id, username, email, roles }
- MessageResponse: { message }

### Create Spring RestAPIs Controllers
**/api/auth/signup**

- check existing username/email
- create new User (with ROLE_USER if not specifying role)
- save User to database using UserRepository
**/api/auth/signin**

- authenticate { username, pasword }
- update SecurityContext using Authentication object
- generate JWT
- get UserDetails from Authentication object
- response contains JWT and UserDetails data

controllers/AuthController.java
```
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import javax.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import com.bezkoder.springjwt.models.ERole;
import com.bezkoder.springjwt.models.Role;
import com.bezkoder.springjwt.models.User;
import com.bezkoder.springjwt.payload.request.LoginRequest;
import com.bezkoder.springjwt.payload.request.SignupRequest;
import com.bezkoder.springjwt.payload.response.JwtResponse;
import com.bezkoder.springjwt.payload.response.MessageResponse;
import com.bezkoder.springjwt.repository.RoleRepository;
import com.bezkoder.springjwt.repository.UserRepository;
import com.bezkoder.springjwt.security.jwt.JwtUtils;
import com.bezkoder.springjwt.security.services.UserDetailsImpl;
@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
public class AuthController {
	@Autowired
	AuthenticationManager authenticationManager;
	@Autowired
	UserRepository userRepository;
	@Autowired
	RoleRepository roleRepository;
	@Autowired
	PasswordEncoder encoder;
	@Autowired
	JwtUtils jwtUtils;
	@PostMapping("/signin")
	public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {
		Authentication authentication = authenticationManager.authenticate(
				new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));
		SecurityContextHolder.getContext().setAuthentication(authentication);
		String jwt = jwtUtils.generateJwtToken(authentication);
		
		UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();		
		List<String> roles = userDetails.getAuthorities().stream()
				.map(item -> item.getAuthority())
				.collect(Collectors.toList());
		return ResponseEntity.ok(new JwtResponse(jwt, 
												 userDetails.getId(), 
												 userDetails.getUsername(), 
												 userDetails.getEmail(), 
												 roles));
	}
	@PostMapping("/signup")
	public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
		if (userRepository.existsByUsername(signUpRequest.getUsername())) {
			return ResponseEntity
					.badRequest()
					.body(new MessageResponse("Error: Username is already taken!"));
		}
		if (userRepository.existsByEmail(signUpRequest.getEmail())) {
			return ResponseEntity
					.badRequest()
					.body(new MessageResponse("Error: Email is already in use!"));
		}
		// Create new user's account
		User user = new User(signUpRequest.getUsername(), 
							 signUpRequest.getEmail(),
							 encoder.encode(signUpRequest.getPassword()));
		Set<String> strRoles = signUpRequest.getRole();
		Set<Role> roles = new HashSet<>();
		if (strRoles == null) {
			Role userRole = roleRepository.findByName(ERole.ROLE_USER)
					.orElseThrow(() -> new RuntimeException("Error: Role is not found."));
			roles.add(userRole);
		} else {
			strRoles.forEach(role -> {
				switch (role) {
				case "admin":
					Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
							.orElseThrow(() -> new RuntimeException("Error: Role is not found."));
					roles.add(adminRole);
					break;
				case "mod":
					Role modRole = roleRepository.findByName(ERole.ROLE_MODERATOR)
							.orElseThrow(() -> new RuntimeException("Error: Role is not found."));
					roles.add(modRole);
					break;
				default:
					Role userRole = roleRepository.findByName(ERole.ROLE_USER)
							.orElseThrow(() -> new RuntimeException("Error: Role is not found."));
					roles.add(userRole);
				}
			});
		}
		user.setRoles(roles);
		userRepository.save(user);
		return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
	}
}
```

### Controller for testing Authorization

There are 4 APIs:
– /api/test/all for public access
– /api/test/user for users has ROLE_USER or ROLE_MODERATOR or ROLE_ADMIN
– /api/test/mod for users has ROLE_MODERATOR
– /api/test/admin for users has ROLE_ADMIN

Bạn có nhớ tôi đã sử dụng @EnableGlobalMethodSecurity(prePostEnabled = true) cho WebSecurityConfig class?
```
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter { ... }
```

Giờ tôi có thể bảo mật các phương thức API với @PreAuthorize một cách dễ dàng.
controllers/TestController.java
```
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/test")
public class TestController {
	@GetMapping("/all")
	public String allAccess() {
		return "Public Content.";
	}
	
	@GetMapping("/user")
	@PreAuthorize("hasRole('USER') or hasRole('MODERATOR') or hasRole('ADMIN')")
	public String userAccess() {
		return "User Content.";
	}
	@GetMapping("/mod")
	@PreAuthorize("hasRole('MODERATOR')")
	public String moderatorAccess() {
		return "Moderator Board.";
	}
	@GetMapping("/admin")
	@PreAuthorize("hasRole('ADMIN')")
	public String adminAccess() {
		return "Admin Board.";
	}
}
```
