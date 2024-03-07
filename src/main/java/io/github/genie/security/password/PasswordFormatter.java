package io.github.genie.security.password;

import io.github.genie.security.format.BinaryFormat;
import io.github.genie.security.format.Encryptor;
import org.jetbrains.annotations.NotNull;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;

import static io.github.genie.security.password.DefaultPasswordSerializer.START_BYTE_VALUE;

public class PasswordFormatter {

    private final Encryptor encryptor;
    private final BinaryFormat binaryFormat;

    public PasswordFormatter(Encryptor encryptor, BinaryFormat binaryFormat) {
        this.encryptor = encryptor;
        this.binaryFormat = binaryFormat;
    }

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
            byte[] encrypt = encryptor.encrypt(bytes);
            return binaryFormat.format(encrypt);
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException(e);
        }
    }

}
