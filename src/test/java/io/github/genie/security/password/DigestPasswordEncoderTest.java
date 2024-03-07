package io.github.genie.security.password;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.Base64;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.ThreadLocalRandom;

class DigestPasswordEncoderTest {

    @Test
    void matches() {

        byte[] password = new byte[16];
        byte[] key = new byte[16];
        ThreadLocalRandom.current().nextBytes(key);
        DigestPasswordEncoder encoder = new DigestPasswordEncoder(key);
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
}