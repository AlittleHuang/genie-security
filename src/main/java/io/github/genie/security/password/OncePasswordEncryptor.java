package io.github.genie.security.password;

import io.github.genie.security.format.BinaryFormat;
import io.github.genie.security.format.Decryptor;
import io.github.genie.security.exception.CipherExpiredException;
import io.github.genie.security.exception.CipherRepeatedlyException;
import io.github.genie.security.password.beans.ExpiredCache;
import io.github.genie.security.password.beans.PasswordDeserializer;
import io.github.genie.security.password.beans.TimeMarkedPassword;
import org.jetbrains.annotations.NotNull;

import java.security.GeneralSecurityException;
import java.time.Duration;

public class OncePasswordEncryptor {

    private final ExpiredCache cache;
    private final long expiryDuration;
    private final Decryptor decryptor;
    private final PasswordDeserializer passwordDeserializer;
    private final BinaryFormat inputFormat;


    public OncePasswordEncryptor(ExpiredCache cache,
                                 Duration validityPeriod,
                                 Decryptor decryptor,
                                 PasswordDeserializer passwordDeserializer,
                                 BinaryFormat inputFormat) {
        this.cache = cache;
        this.expiryDuration = validityPeriod.toMillis();
        this.decryptor = decryptor;
        this.passwordDeserializer = passwordDeserializer;
        this.inputFormat = inputFormat;
    }

    public @NotNull String decrypt(@NotNull String ciphertext) throws GeneralSecurityException {
        if (cache.exist(ciphertext)) {
            throw new CipherRepeatedlyException("the ciphertext is decrypted repeatedly");
        }
        byte[] decrypt = decryptor.decrypt(inputFormat.parse(ciphertext));
        TimeMarkedPassword password = passwordDeserializer.deserialize(decrypt);
        long now = System.currentTimeMillis();
        long expiry = password.getCreateTime() + this.expiryDuration;
        if (now > expiry) {
            throw new CipherExpiredException("the ciphertext is expired");
        }
        cache.put(ciphertext, expiry);
        return password.getPassword();
    }

}
