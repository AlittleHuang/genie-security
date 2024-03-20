package io.github.genie.security.format;

import org.jetbrains.annotations.NotNull;

/**
 * binary encoding format
 *
 * @see Base64Format
 * @see HexFormat
 */
public interface BinaryFormat {
    /**
     * format data
     *
     * @param input binary input
     * @return string output
     */
    @NotNull String format(byte @NotNull [] input);

    /**
     * parse data
     *
     * @param format string format
     * @return binary data
     * @throws IllegalArgumentException the input ciphertext cannot be parsed.
     */
    byte @NotNull [] parse(@NotNull String format) throws IllegalArgumentException;
}
