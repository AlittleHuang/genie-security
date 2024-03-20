package io.github.genie.security.format;

import org.jetbrains.annotations.NotNull;

/**
 * decryptor
 *
 * @see Decryptor
 */
public interface Encryptor {

    /**
     * encrypt data
     *
     * @param plaintext plaintext
     * @return ciphertext
     * @see Decryptor#decrypt(byte[])
     */
    byte @NotNull [] encrypt(byte @NotNull [] plaintext);

}
