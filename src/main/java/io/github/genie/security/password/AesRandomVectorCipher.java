package io.github.genie.security.password;

import io.github.genie.security.format.Decryptor;
import io.github.genie.security.format.Encryptor;
import io.github.genie.security.format.HexFormat;

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
    public byte[] decrypt(byte[] coded) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        IvParameterSpec iv = new IvParameterSpec(coded, 0, 16);
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        return cipher.doFinal(coded, 16, coded.length - 16);
    }

    @Override
    public byte[] encrypt(byte[] raw) throws GeneralSecurityException {
        byte[] iv = SecureRandom.getInstanceStrong().generateSeed(16);
        IvParameterSpec ips = new IvParameterSpec(iv);
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, key, ips);
        int outputSize = cipher.getOutputSize(raw.length);
        byte[] output = new byte[iv.length + outputSize];
        cipher.doFinal(raw, 0, raw.length, output, iv.length);
        System.arraycopy(iv, 0, output, 0, iv.length);
        return output;
    }

}
