package io.github.genie.security.password;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;

public class DefaultPasswordSerializer implements PasswordDeserializer {
    public static final byte START_BYTE_VALUE = (byte) 0xff;

    private final Duration timeToLive;

    public DefaultPasswordSerializer(Duration timeToLive) {
        if (timeToLive.compareTo(Duration.ZERO) <= 0) {
            throw new IllegalArgumentException();
        }
        this.timeToLive = timeToLive;
    }


    @Override
    public ExpirablePassword deserialize(byte[] decrypt) {
        int paddingLength = paddingLength(decrypt);
        ByteBuffer buffer = ByteBuffer.wrap(decrypt, paddingLength, decrypt.length - paddingLength);
        long createTime = buffer.getLong();
        int pwdOffset = Long.BYTES + paddingLength;
        String rawPassword = new String(decrypt, pwdOffset, decrypt.length - pwdOffset, StandardCharsets.UTF_8);
        return new Password(createTime, rawPassword, timeToLive);
    }

    private static int paddingLength(byte[] decrypt) {
        for (int i = 0; i < decrypt.length; i++) {
            if (decrypt[i] == START_BYTE_VALUE) {
                return i + 1;
            }
        }
        throw new IllegalArgumentException();
    }

    protected static final class Password implements ExpirablePassword {
        public final long createTime;
        public final String rawPassword;
        private final Instant expiry;

        public Password(long createTime, String rawPassword, Duration timeToLive) {
            this.createTime = createTime;
            this.rawPassword = rawPassword;
            Instant create = Instant.ofEpochMilli(createTime);
            this.expiry = create.plus(timeToLive);
        }

        @Override
        public Instant expiry() {
            return expiry;
        }

        @Override
        public String password() {
            return rawPassword;
        }
    }
}
