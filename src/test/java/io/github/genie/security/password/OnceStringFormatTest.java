package io.github.genie.security.password;

import io.github.genie.security.format.Base64Format;
import io.github.genie.security.format.HexFormat;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.LockSupport;

class OnceStringFormatTest {

    private static final String key = "1f33de43ce4011d95e6a4d059a93873468dc100b8d100843c41b71ed16e1fc96";
    private static final OncePasswordFormat hex = new OncePasswordFormat(
            new SimpleCache(), HexFormat.of().parse(key), Duration.ofSeconds(1), HexFormat.of());

    private static final OncePasswordFormat base64 = new OncePasswordFormat(
            new SimpleCache(), HexFormat.of().parse(key), Duration.ofSeconds(1), Base64Format.of());


    @Test
    void codec() {
        codec(hex);
        codec(base64);
    }

    private static void codec(OncePasswordFormat format) {
        String password = "";
        for (int i = 0; i < 1000; i++) {
            if (i == 147) {
                System.out.println();
            }
            password += key.charAt(i % key.length());
            String encode = format.format(password);
            String string = format.parse(encode);
            if (!password.equals(string)) {
                System.out.println(string);
            }
            Assertions.assertEquals(password, string);
        }
    }

    @Test
    void onceCheck() {
        String encode = hex.format("pwd");
        Assertions.assertNotNull(hex.parse(encode));
        Assertions.assertThrowsExactly(IllegalArgumentException.class, () -> hex.parse(encode));
    }

    @Test
    void timeout() {
        String encode = hex.format("pwd");
        LockSupport.parkNanos(TimeUnit.SECONDS.toNanos(1));
        Assertions.assertThrowsExactly(IllegalArgumentException.class, () -> hex.parse(encode));
    }

    @Test
    void crash() {
        int count = 10000;
        int capacity = count * 2;
        Set<String> set = new HashSet<>(capacity);
        for (int i = 0; i < count; i++) {
            String format = hex.format("");
            set.add(format);
        }
        Assertions.assertEquals(count, set.size());
    }

}