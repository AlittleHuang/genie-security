package io.github.genie.security.password;

import org.jetbrains.annotations.NotNull;

public interface PasswordEncoder {
    @NotNull String encode(CharSequence rawPassword);

    boolean matches(@NotNull CharSequence rawPassword, @NotNull String encodedPassword);
}
