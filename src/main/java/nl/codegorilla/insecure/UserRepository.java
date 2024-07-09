package nl.codegorilla.insecure;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

//public interface UserRepository extends JpaRepository<User, Long> {
//    User findByUsername(String username);
//}

@Component
public class UserRepository {
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
