package io.github.genie.security.password;

import io.github.genie.security.format.BinaryFormat;
import org.jetbrains.annotations.NotNull;

import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.time.Duration;

public class OncePasswordFormat implements PasswordFormat {
    public static final byte START_BYTE_VALUE = (byte) 0xff;
    private final ExpiredPasswordCache cache;
    private final SecretKeySpec keySpec;
    private final long timeToLive;
    private final BinaryFormat binaryFormat;

    public OncePasswordFormat(ExpiredPasswordCache cache,
                              byte[] key,
                              Duration timeToLive,
                              BinaryFormat format) {
        this.cache = cache;
        this.keySpec = new SecretKeySpec(key, "AES");
        this.timeToLive = timeToLive.toMillis();
        this.binaryFormat = format;
    }

    @Override
    public @NotNull String format(@NotNull String rawPassword) {
        byte[] pwd = rawPassword.getBytes(StandardCharsets.UTF_8);
        int pwdBytes = pwd.length;

        int dataLen = 1 + Long.BYTES + pwdBytes;
        byte[] bytes = new byte[Math.max(dataLen, 47)];
        int offset = bytes.length - dataLen;
        ByteBuffer buffer = ByteBuffer.wrap(bytes, offset, bytes.length - offset);
        buffer.put(START_BYTE_VALUE);
        buffer.putLong(System.currentTimeMillis());
        buffer.put(pwd);
        try {
            byte[] encrypt = EncryptionUtil.encrypt(keySpec, bytes);
            return binaryFormat.format(encrypt);
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException(e);
        }
    }

    @Override
    public @NotNull String parse(@NotNull String encodedPassword) throws IllegalArgumentException {
        try {
            if (cache.exist(encodedPassword)) {
                throw new IllegalArgumentException("used");
            }
            byte[] decrypt = EncryptionUtil.decrypt(keySpec, binaryFormat.parse(encodedPassword));
            Password password = of(decrypt);
            long life = System.currentTimeMillis() - password.createTime;
            if (life < 0) {
                of(decrypt);
                throw new IllegalArgumentException("create time is after now");
            }
            if (life > timeToLive) {
                throw new IllegalArgumentException("expired");
            }
            cache.put(encodedPassword, Duration.ofMillis(timeToLive));
            return password.rawPassword;
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException(e);
        }
    }

    protected Password of(byte[] decrypt) {
        int paddingLength = paddingLength(decrypt);
        ByteBuffer buffer = ByteBuffer.wrap(decrypt, paddingLength, decrypt.length - paddingLength);
        long createTime = buffer.getLong();
        int pwdOffset = Long.BYTES + paddingLength;
        String rawPassword = new String(decrypt, pwdOffset, decrypt.length - pwdOffset, StandardCharsets.UTF_8);
        return new Password(createTime, rawPassword);
    }

    private static int paddingLength(byte[] decrypt) {
        for (int i = 0; i < decrypt.length; i++) {
            if (decrypt[i] == START_BYTE_VALUE) {
                return i + 1;
            }
        }
        throw new IllegalArgumentException();
    }

    protected static final class Password {
        public final long createTime;
        public final String rawPassword;

        public Password(long createTime, String rawPassword) {
            this.createTime = createTime;
            this.rawPassword = rawPassword;
        }
    }

}
