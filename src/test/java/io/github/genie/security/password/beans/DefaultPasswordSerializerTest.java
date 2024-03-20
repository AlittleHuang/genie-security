package io.github.genie.security.password.beans;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * @author HuangChengwei
 * @since 2024-03-20 11:23
 */
class DefaultPasswordSerializerTest {

    @Test
    void serialize() {
        DefaultPasswordSerializer serializer = new DefaultPasswordSerializer();
        test(serializer, "12345");
        test(serializer, "中文");
        test(serializer, "😊");
        test(serializer, "12345中文😊");
    }

    private static void test(DefaultPasswordSerializer serializer, String input) {
        TimeMarkedPassword password = new TimeMarkedPassword(input);
        byte[] serialize = serializer.serialize(password);
        TimeMarkedPassword password1 = serializer.deserialize(serialize);
        Assertions.assertEquals(password.getPassword(), password1.getPassword());
        Assertions.assertEquals(password.getCreateTime(), password1.getCreateTime());
    }
}