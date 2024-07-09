package nl.codegorilla.insecure;

public record User(
        Long id,
        String username,
        String password,
        String secret) {
}
