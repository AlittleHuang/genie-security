package io.github.genie.security.password;

import org.jetbrains.annotations.NotNull;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Objects;
import java.util.concurrent.ThreadLocalRandom;

public class FastPasswordEncoder implements PasswordEncoder {

    public static final int DEFAULT_SALT_LENGTH = Long.BYTES * 2;
    public static final String DEFAULT_ALGORITHM = "SHA-256";

    public final int saltLength;
    private final byte[] key;
    private final String algorithm;

    public FastPasswordEncoder(byte[] key) {
        this(key, DEFAULT_SALT_LENGTH, DEFAULT_ALGORITHM);
    }

    public FastPasswordEncoder(byte[] key, int saltLength, String algorithm) {
        this.saltLength = saltLength;
        this.key = key;
        this.algorithm = algorithm;
        getMessageDigest();
    }

    @Override
    public @NotNull String encode(CharSequence rawPassword) {
        return doEncode(rawPassword, getRandomBytes());
    }

    private byte[] getRandomBytes() {
        byte[] randomBytes = new byte[saltLength];
        ThreadLocalRandom.current().nextBytes(randomBytes);
        return randomBytes;
    }

    protected String doEncode(CharSequence rawPassword, byte[] random) {
        byte[] src = rawPassword.toString().getBytes(StandardCharsets.UTF_8);
        MessageDigest digest = getMessageDigest();
        digest.update(src);
        digest.update(random, 0, saltLength);
        digest.update(key);
        byte[] digestBytes = digest.digest();
        byte[] dist = new byte[saltLength + digestBytes.length];
        System.arraycopy(random, 0, dist, 0, saltLength);
        System.arraycopy(digestBytes, 0, dist, saltLength, digestBytes.length);
        return Base64.getEncoder().encodeToString(dist);
    }

    private MessageDigest getMessageDigest() {
        try {
            return MessageDigest.getInstance(algorithm);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public boolean matches(@NotNull CharSequence rawPassword, @NotNull String encodedPassword) {
        try {
            byte[] decode = Base64.getDecoder().decode(encodedPassword);
            String expected = doEncode(rawPassword, decode);
            return Objects.equals(encodedPassword, expected);
        } catch (Exception e) {
            return false;
        }
    }

}
