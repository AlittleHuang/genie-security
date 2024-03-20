package io.github.genie.security.password.beans;

import io.github.genie.security.exception.UncheckedSecurityException;
import io.github.genie.security.format.Base64Format;
import io.github.genie.security.format.BinaryFormat;
import io.github.genie.security.password.PasswordEncoder;
import org.jetbrains.annotations.NotNull;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.concurrent.ThreadLocalRandom;

public class DigestEncoder implements PasswordEncoder {

    public static final int DEFAULT_SALT_BYTES = Long.BYTES * 2;
    public static final String DEFAULT_ALGORITHM = "SHA-256";
    public static final Base64Format DEFAULT_FORMAT = Base64Format.of();

    public final int saltLength;
    private final byte[] key;
    private final String algorithm;
    private final BinaryFormat format;

    public DigestEncoder(byte[] key) {
        this(key, DEFAULT_SALT_BYTES, DEFAULT_ALGORITHM, DEFAULT_FORMAT);
    }

    public DigestEncoder(byte[] key,
                         int saltLength,
                         String algorithm,
                         BinaryFormat format) {
        this.saltLength = saltLength;
        this.key = key;
        this.algorithm = algorithm;
        this.format = format;
        getMessageDigest();
    }

    @Override
    public @NotNull String encode(CharSequence rawPassword) {
        byte[] bytes = digest(rawPassword, getRandomBytes());
        return format.format(bytes);
    }

    private byte[] getRandomBytes() {
        byte[] randomBytes = new byte[saltLength];
        ThreadLocalRandom.current().nextBytes(randomBytes);
        return randomBytes;
    }

    protected byte[] digest(CharSequence rawPassword, byte[] random) {
        byte[] src = rawPassword.toString().getBytes(StandardCharsets.UTF_8);
        MessageDigest digest = getMessageDigest();
        digest.update(src);
        digest.update(random, 0, saltLength);
        digest.update(key);
        byte[] digestBytes = digest.digest();
        byte[] dist = new byte[saltLength + digestBytes.length];
        System.arraycopy(random, 0, dist, 0, saltLength);
        System.arraycopy(digestBytes, 0, dist, saltLength, digestBytes.length);
        return dist;
    }

    private MessageDigest getMessageDigest() {
        try {
            return MessageDigest.getInstance(algorithm);
        } catch (NoSuchAlgorithmException e) {
            throw new UncheckedSecurityException(e);
        }
    }

    @Override
    public boolean matches(@NotNull CharSequence rawPassword, @NotNull String encodedPassword) {
        try {
            byte[] expected = format.parse(encodedPassword);
            byte[] actual = digest(rawPassword, expected);
            return Arrays.equals(expected, actual);
        } catch (Exception e) {
            return false;
        }
    }

}
