package io.github.genie.security.password;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;

class EncryptionUtil {

    public static final String TRANSFORMATION = "AES/CBC/PKCS5Padding";

    public static byte[] encrypt(SecretKeySpec key, byte[] input) throws GeneralSecurityException {
        SecureRandom sr = SecureRandom.getInstanceStrong();
        byte[] iv = sr.generateSeed(16);
        return encrypt(key, iv, input);
    }

    private static byte[] encrypt(SecretKeySpec keySpec, byte[] iv, byte[] input) throws GeneralSecurityException {
        IvParameterSpec ips = new IvParameterSpec(iv);
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ips);
        int outputSize = cipher.getOutputSize(input.length);
        byte[] output = new byte[iv.length + outputSize];
        cipher.doFinal(input, 0, input.length, output, iv.length);
        System.arraycopy(iv, 0, output, 0, iv.length);
        return output;
    }

    public static byte[] decrypt(SecretKeySpec keySpec, byte[] input) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        IvParameterSpec iv = new IvParameterSpec(input, 0, 16);
        cipher.init(Cipher.DECRYPT_MODE, keySpec, iv);
        return cipher.doFinal(input, 16, input.length - 16);
    }

}
