package io.github.genie.security.password;

import io.github.genie.security.format.BinaryFormat;
import io.github.genie.security.format.Decryptor;
import org.jetbrains.annotations.NotNull;

import java.security.GeneralSecurityException;
import java.time.Instant;

public class OncePasswordParser {

    private final ExpiredPasswordCache cache;
    private final Decryptor decryptor;
    private final PasswordDeserializer passwordDeserializer;
    private final BinaryFormat binaryFormat;

    public OncePasswordParser(ExpiredPasswordCache cache,
                              Decryptor decryptor,
                              PasswordDeserializer passwordDeserializer,
                              BinaryFormat format) {
        this.cache = cache;
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
            ExpirablePassword password = passwordDeserializer.deserialize(decrypt);
            Instant now = Instant.now();
            Instant expiry = password.expiry();
            if (now.isAfter(expiry)) {
                throw new IllegalArgumentException("expired,now:" + now + ", expiry:" + expiry);
            }
            cache.put(encodedPassword, expiry);
            return password.password();
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException(e);
        }
    }

}
