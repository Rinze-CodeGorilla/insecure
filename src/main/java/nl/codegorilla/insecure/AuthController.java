package nl.codegorilla.insecure;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.constraints.NotBlank;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

@Controller
public class AuthController {
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
    String login(String username, String password, HttpServletResponse response, Model model) {
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
