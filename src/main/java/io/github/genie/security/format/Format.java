package io.github.genie.security.format;

import org.jetbrains.annotations.NotNull;

public interface Format<I, O> {

    @NotNull
    O format(@NotNull I rawPassword);

    @NotNull
    I parse(@NotNull O encodedPassword) throws IllegalArgumentException;

}
