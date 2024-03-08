package io.github.genie.security.password.beans;

import org.jetbrains.annotations.NotNull;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class DefaultPasswordSerializer implements PasswordSerializer, PasswordDeserializer {

    @Override
    public TimeMarkedPassword deserialize(byte[] bytes) {
        bytes = Base64.getDecoder().decode(bytes);
        ByteBuffer buffer = ByteBuffer.wrap(bytes);
        long createTime = buffer.getLong();
        int pwdOffset = Long.BYTES;
        String rawPassword = new String(bytes, pwdOffset, bytes.length - pwdOffset, StandardCharsets.UTF_8);
        return new TimeMarkedPassword(rawPassword, createTime);
    }

    @Override
    public byte[] serialize(@NotNull TimeMarkedPassword password) {
        byte[] pwd = password.getPassword().getBytes(StandardCharsets.UTF_8);
        int pwdBytes = pwd.length;
        byte[] bytes = new byte[Long.BYTES + pwdBytes];
        ByteBuffer buffer = ByteBuffer.wrap(bytes);
        buffer.putLong(password.getCreateTime());
        buffer.put(pwd);

        return Base64.getEncoder().encode(bytes);
    }
}
