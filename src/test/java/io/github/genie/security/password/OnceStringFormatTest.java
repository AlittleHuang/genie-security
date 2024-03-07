package io.github.genie.security.password;

import io.github.genie.security.format.Base64Format;
import io.github.genie.security.format.HexFormat;
import io.github.genie.security.password.beans.AesRandomVectorCipher;
import io.github.genie.security.password.beans.DefaultPasswordSerializer;
import io.github.genie.security.password.beans.SimpleCache;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.LockSupport;

class OnceStringFormatTest {

    private static final String key = "1f33de43ce4011d95e6a4d059a93873468dc100b8d100843c41b71ed16e1fc96";
    public static final AesRandomVectorCipher DECRYPTOR = AesRandomVectorCipher.hexKey(key);
    public static final Duration TIME_TO_LIVE = Duration.ofMillis(10);
    public static final DefaultPasswordSerializer SERIALIZER = new DefaultPasswordSerializer();
    private static final OncePasswordParser hex = new OncePasswordParser(
            new SimpleCache(), TIME_TO_LIVE, DECRYPTOR, SERIALIZER, HexFormat.of());

    public static final PasswordFormatter hexFormatter = new PasswordFormatter(DECRYPTOR, HexFormat.of(), SERIALIZER);

    private static final OncePasswordParser base64 = new OncePasswordParser(
            new SimpleCache(), TIME_TO_LIVE, DECRYPTOR, SERIALIZER, Base64Format.of());
    public static final PasswordFormatter base64Formatter =
            new PasswordFormatter(DECRYPTOR, Base64Format.of(), SERIALIZER);


    @Test
    void codec() {
        codec(hex, hexFormatter);
        codec(base64, base64Formatter);
    }

    private static void codec(OncePasswordParser parser, PasswordFormatter formatter) {
        String password = "";
        for (int i = 0; i < 1000; i++) {
            password += key.charAt(i % key.length());
            String encode = formatter.format(password);
            String string = parser.parse(encode);
            Assertions.assertEquals(password, string);
        }
    }

    @Test
    void onceCheck() {
        String encode = hexFormatter.format("pwd");
        Assertions.assertNotNull(hex.parse(encode));
        Assertions.assertThrowsExactly(IllegalArgumentException.class, () -> hex.parse(encode));
    }

    @Test
    void timeout() {
        String encode = hexFormatter.format("pwd");
        LockSupport.parkNanos(TimeUnit.MILLISECONDS.toNanos(TIME_TO_LIVE.toMillis()));
        Assertions.assertThrowsExactly(IllegalArgumentException.class, () -> hex.parse(encode));
    }

    @Test
    void crash() {
        int count = 10000;
        int capacity = count * 2;
        Set<String> set = new HashSet<>(capacity);
        for (int i = 0; i < count; i++) {
            String format = hexFormatter.format("");
            set.add(format);
        }
        Assertions.assertEquals(count, set.size());
    }

}