package nl.codegorilla.insecure;

import jakarta.servlet.DispatcherType;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.constraints.NotBlank;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.context.NullSecurityContextRepository;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Controller;
import org.springframework.stereotype.Service;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.springframework.security.core.userdetails.User.withUsername;

//interface UserRepository extends JpaRepository<User, Long> {
//    User findByUsername(String username);
//}
//class InMemoryUserDetailsService implements UserDetailsService {
//    @Override
//    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
//        return null;
//    }
//}

@Component
class UserRepository {
    ArrayList<User> users = new ArrayList<>();

    UserRepository(@Autowired PasswordEncoder passwordEncoder) {
        users.add(new User(0L, "Rinze", passwordEncoder.encode("p@ssw0rd"), "I secretly enjoy ******"));
    }

    User findByUsername(String username) {
        return users.stream().filter(u -> u.username().equals(username)).findFirst().orElse(null);
    }

    User findById(Long id) {
        return users.get(id.intValue());
    }

    User save(User user) {
        if (user.id() == null) {
            User saved = new User(Long.valueOf(users.size()), user.username(), user.password(), user.secret());
            users.add(saved);
            return saved;
        } else {
            users.add(user.id().intValue(), user);
            return user;
        }
    }

    List<User> findAll() {
        return users;
    }
}

@SpringBootApplication
public class InsecureApplication {
    public static void main(String[] args) {
        SpringApplication.run(InsecureApplication.class, args);
    }
}

//@Entity
record User(
//        @Id
//        @GeneratedValue(strategy = GenerationType.IDENTITY)
        Long id,
        String username,
        String password,
        String secret) {
}

@Service
class UserService implements UserDetailsService {
    @Autowired
    UserRepository userRepository;

    public User findByUsername(String username) {
        return userRepository.findByUsername(username);
    }

    public User findById(long id) {
        return userRepository.findById(id);
    }

    public User save(User user) {
        return userRepository.save(user);
    }

    public List<User> findAll() {
        return userRepository.findAll();
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username);
        if (user == null) {
            throw new UsernameNotFoundException(username + " not found");
        }
        return withUsername(user.username()).password(user.password()).authorities("USER").build();
    }
}

@Configuration
@EnableWebSecurity
class SecurityConfig {
    @Autowired
    UserService userService;
    @Autowired
    CookieAuthenticationFilter cookieAuthenticationFilter;

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.csrf(AbstractHttpConfigurer::disable)
                .authorizeRequests(authorize -> authorize
                                .requestMatchers("/").authenticated()
                                .requestMatchers("/admin").authenticated()
                                .anyRequest().permitAll()
                );
        http.addFilterBefore(cookieAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }
}

@Configuration
class IndependentConfig {
    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}

@Component
class CookieAuthenticationFilter extends OncePerRequestFilter {

    @Autowired
    UserService userService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        if (request.getCookies() != null) Arrays.stream(request.getCookies()).filter(c -> "USER_ID".equals(c.getName())).findFirst().ifPresent(c -> {
            var user = userService.findById(Long.parseLong(c.getValue()));
            var auth = new UsernamePasswordAuthenticationToken(userService.loadUserByUsername(user.username()), null, null);
            auth.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
            SecurityContextHolder.getContext().setAuthentication(auth);
        });
        filterChain.doFilter(request, response);
    }
}

@Controller
class WebController {
    @Autowired
    UserService userService;

    @GetMapping("/")
    String index(Model model) {
        User user = userService.findByUsername(SecurityContextHolder.getContext().getAuthentication().getName());
        if (user != null) {
            model.addAttribute("username", user.username());
            model.addAttribute("isAdmin", user.id() == 0);
        }
        return "index";
    }

    @GetMapping("/admin")
    String admin(Model model) {
        model.addAttribute("users", userService.findAll());
        return "admin";
    }
}

@Controller
class AuthController {
    @Autowired
    UserService userService;
    @Autowired
    PasswordEncoder passwordEncoder;

    @GetMapping("/login")
    String login() {
        return "login";
    }

    @GetMapping("/register")
    String register() {
        return "register";
    }

    @PostMapping("/register")
    String register(@NotBlank String username, @NotBlank String password, @NotBlank String secret) {
        User user = userService.findByUsername(username);
        if (user == null) {
            user = new User(null, username, passwordEncoder.encode(password), secret);
        }
        userService.save(user);
        return "redirect:/login";
    }

    @PostMapping("/login")
    String postLogin(String username, String password, HttpServletResponse response, Model model) {
        var user = userService.findByUsername(username);
        if (user != null && passwordEncoder.matches(password, user.password())) {
            Cookie cookie = new Cookie("USER_ID", user.id().toString());
            cookie.setPath("/");
            cookie.setMaxAge(7 * 24 * 60 * 60);
            response.addCookie(cookie);
            return "redirect:/";
        } else {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            model.addAttribute("error", "Invalid username or password");
            return "login";
        }
    }
}