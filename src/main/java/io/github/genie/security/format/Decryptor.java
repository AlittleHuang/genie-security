package io.github.genie.security.format;

import org.jetbrains.annotations.NotNull;

import java.security.GeneralSecurityException;

/**
 * decryptor
 *
 * @see Encryptor
 */
public interface Decryptor {

    /**
     * decrypt data
     *
     * @param ciphertext ciphertext
     * @return plaintext
     * @throws GeneralSecurityException the input ciphertext cannot be decrypted.
     * @see Encryptor#encrypt(byte[])
     */
    byte @NotNull [] decrypt(byte @NotNull [] ciphertext) throws GeneralSecurityException;

}
