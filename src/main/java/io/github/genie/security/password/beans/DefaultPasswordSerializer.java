package io.github.genie.security.password.beans;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

public class DefaultPasswordSerializer implements PasswordSerializer, PasswordDeserializer {
    public static final byte START_BYTE_VALUE = (byte) 0xff;

    @Override
    public TimeMarkedPassword deserialize(byte[] bytes) {
        int paddingLength = paddingLength(bytes);
        ByteBuffer buffer = ByteBuffer.wrap(bytes, paddingLength, bytes.length - paddingLength);
        long createTime = buffer.getLong();
        int pwdOffset = Long.BYTES + paddingLength;
        String rawPassword = new String(bytes, pwdOffset, bytes.length - pwdOffset, StandardCharsets.UTF_8);
        return new TimeMarkedPassword(rawPassword, createTime);
    }

    private static int paddingLength(byte[] decrypt) {
        for (int i = 0; i < decrypt.length; i++) {
            if (decrypt[i] == START_BYTE_VALUE) {
                return i + 1;
            }
        }
        throw new IllegalArgumentException();
    }

    @Override
    public byte[] serialize(TimeMarkedPassword password) {
        byte[] pwd = password.getPassword().getBytes(StandardCharsets.UTF_8);
        int pwdBytes = pwd.length;

        int dataLen = 1 + Long.BYTES + pwdBytes;
        byte[] bytes = new byte[Math.max(dataLen, 47)];
        int offset = bytes.length - dataLen;
        ByteBuffer buffer = ByteBuffer.wrap(bytes, offset, bytes.length - offset);
        buffer.put(START_BYTE_VALUE);
        buffer.putLong(password.getCreateTime());
        buffer.put(pwd);
        return bytes;
    }
}
