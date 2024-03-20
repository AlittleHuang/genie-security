package io.github.genie.security.password.beans;

import io.github.genie.security.exception.UncheckedSecurityException;
import io.github.genie.security.format.Decryptor;
import io.github.genie.security.format.Encryptor;
import io.github.genie.security.format.HexFormat;
import org.jetbrains.annotations.NotNull;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;

public class AesRandomVectorCipher implements Decryptor, Encryptor {
    public static final String TRANSFORMATION = "AES/CBC/PKCS5Padding";
    private final SecretKeySpec key;

    public static AesRandomVectorCipher hexKey(String hexKey) {
        return new AesRandomVectorCipher(HexFormat.of().parse(hexKey));
    }

    public AesRandomVectorCipher(byte[] key) {
        this(new SecretKeySpec(key, "AES"));
    }

    public AesRandomVectorCipher(SecretKeySpec key) {
        this.key = key;
    }

    @Override
    public byte @NotNull [] decrypt(byte @NotNull [] ciphertext) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        IvParameterSpec iv = new IvParameterSpec(ciphertext, 0, 16);
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        return cipher.doFinal(ciphertext, 16, ciphertext.length - 16);
    }

    @Override
    public byte @NotNull [] encrypt(byte @NotNull [] plaintext) {
        try {
            byte[] iv = SecureRandom.getInstanceStrong().generateSeed(16);
            IvParameterSpec ips = new IvParameterSpec(iv);
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, key, ips);
            int outputSize = cipher.getOutputSize(plaintext.length);
            byte[] output = new byte[iv.length + outputSize];
            cipher.doFinal(plaintext, 0, plaintext.length, output, iv.length);
            System.arraycopy(iv, 0, output, 0, iv.length);
            return output;
        } catch (GeneralSecurityException e) {
            throw new UncheckedSecurityException(e);
        }
    }

}
