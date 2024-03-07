package io.github.genie.security.password;

import io.github.genie.security.password.beans.PasswordDigest;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.Base64;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.ThreadLocalRandom;

class PasswordDigestTest {

    @Test
    void matches() {

        byte[] password = new byte[16];
        PasswordEncoder encoder = getEncoder();
        Set<Object> set = new HashSet<>();
        int count = 10000;
        String rawPassword = Base64.getEncoder().encodeToString(password);
        for (int i = 0; i < count; i++) {
            String encode = encoder.encode(rawPassword);
            Assertions.assertTrue(encoder.matches(rawPassword, encode));
            set.add(encode);
        }
        Assertions.assertEquals(set.size(), count);

    }

    @NotNull
    private static PasswordEncoder getEncoder() {
        byte[] key = new byte[16];
        ThreadLocalRandom.current().nextBytes(key);
        return new PasswordDigest(key);
    }


    @Test
    void crash() {
        int count = 10000;
        int capacity = count * 2;
        Set<String> set = new HashSet<>(capacity);
        PasswordEncoder encoder = getEncoder();
        for (int i = 0; i < count; i++) {
            String format = encoder.encode("");
            set.add(format);
        }
        Assertions.assertEquals(count, set.size());
    }
}