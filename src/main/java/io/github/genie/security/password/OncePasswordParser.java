package io.github.genie.security.password;

import io.github.genie.security.format.BinaryFormat;
import io.github.genie.security.format.Decryptor;
import io.github.genie.security.password.beans.ExpiredPasswordCache;
import io.github.genie.security.password.beans.PasswordDeserializer;
import io.github.genie.security.password.beans.TimeMarkedPassword;
import org.jetbrains.annotations.NotNull;

import java.security.GeneralSecurityException;
import java.time.Duration;

public class OncePasswordParser {

    private final ExpiredPasswordCache cache;
    private final long expiryDuration;
    private final Decryptor decryptor;
    private final PasswordDeserializer passwordDeserializer;
    private final BinaryFormat binaryFormat;


    public OncePasswordParser(ExpiredPasswordCache cache,
                              Duration expiry,
                              Decryptor decryptor,
                              PasswordDeserializer passwordDeserializer,
                              BinaryFormat format) {
        this.cache = cache;
        this.expiryDuration = expiry.toMillis();
        this.decryptor = decryptor;
        this.passwordDeserializer = passwordDeserializer;
        this.binaryFormat = format;
    }

    public @NotNull String parse(@NotNull String encodedPassword) throws IllegalArgumentException {
        try {
            if (cache.exist(encodedPassword)) {
                throw new IllegalArgumentException("used");
            }
            byte[] decrypt = decryptor.decrypt(binaryFormat.parse(encodedPassword));
            TimeMarkedPassword password = passwordDeserializer.deserialize(decrypt);
            long now = System.currentTimeMillis();
            long expiry = password.getCreateTime() + this.expiryDuration;
            if (now > expiry) {
                throw new IllegalArgumentException("expired");
            }
            cache.put(encodedPassword, expiry);
            return password.getPassword();
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException(e);
        }
    }

}
