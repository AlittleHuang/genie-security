package io.github.genie.security.password;

import io.github.genie.security.format.BinaryFormat;
import io.github.genie.security.format.Encryptor;
import io.github.genie.security.password.beans.PasswordSerializer;
import io.github.genie.security.password.beans.TimeMarkedPassword;
import org.jetbrains.annotations.NotNull;

public class PasswordEncryptor {
    private final Encryptor encryptor;
    private final BinaryFormat outputFormat;
    private final PasswordSerializer passwordSerializer;

    public PasswordEncryptor(Encryptor encryptor,
                             BinaryFormat outputFormat,
                             PasswordSerializer passwordSerializer) {
        this.encryptor = encryptor;
        this.outputFormat = outputFormat;
        this.passwordSerializer = passwordSerializer;
    }

    public @NotNull String encrypt(@NotNull String plaintext) {
        TimeMarkedPassword password = new TimeMarkedPassword(plaintext);
        byte[] bytes = passwordSerializer.serialize(password);
        byte[] encrypt = encryptor.encrypt(bytes);
        return outputFormat.format(encrypt);
    }

}
