package io.github.genie.security.format;

import org.jetbrains.annotations.NotNull;

public interface Format<I, O> {

    @NotNull
    O format(@NotNull I raw);

    @NotNull
    I parse(@NotNull O format) throws IllegalArgumentException;

}
