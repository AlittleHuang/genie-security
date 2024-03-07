package io.github.genie.security.password;

import io.github.genie.security.format.BinaryFormat;
import io.github.genie.security.format.Encryptor;
import io.github.genie.security.password.beans.PasswordSerializer;
import io.github.genie.security.password.beans.TimeMarkedPassword;
import org.jetbrains.annotations.NotNull;

import java.security.GeneralSecurityException;

public class PasswordFormatter {
    private final Encryptor encryptor;
    private final BinaryFormat binaryFormat;
    private final PasswordSerializer passwordSerializer;

    public PasswordFormatter(Encryptor encryptor,
                             BinaryFormat binaryFormat,
                             PasswordSerializer passwordSerializer) {
        this.encryptor = encryptor;
        this.binaryFormat = binaryFormat;
        this.passwordSerializer = passwordSerializer;
    }

    public @NotNull String format(@NotNull String rawPassword) {
        TimeMarkedPassword password = new TimeMarkedPassword(rawPassword);
        byte[] bytes = passwordSerializer.serialize(password);
        try {
            byte[] encrypt = encryptor.encrypt(bytes);
            return binaryFormat.format(encrypt);
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException(e);
        }
    }

}
