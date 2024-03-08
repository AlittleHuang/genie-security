package io.github.genie.security.password.beans;

import org.jetbrains.annotations.NotNull;

public interface PasswordSerializer {

    byte[] serialize(@NotNull TimeMarkedPassword password);

}
