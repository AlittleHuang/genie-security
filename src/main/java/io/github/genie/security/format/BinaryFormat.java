package io.github.genie.security.format;

import org.jetbrains.annotations.NotNull;

public interface BinaryFormat {
    @NotNull String format(byte @NotNull [] raw);

    byte @NotNull [] parse(@NotNull String format) throws IllegalArgumentException;
}
