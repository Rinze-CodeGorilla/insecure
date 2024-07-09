package nl.codegorilla.insecure;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class WebController {
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
