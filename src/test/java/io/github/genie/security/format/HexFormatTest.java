package io.github.genie.security.format;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrowsExactly;

/**
 * @author HuangChengwei
 * @since 2024-03-20 11:30
 */
class HexFormatTest {

    @Test
    void parse() {
        HexFormat hex = HexFormat.of();
        assertThrowsExactly(IllegalArgumentException.class, () -> hex.parse("a"));
        assertThrowsExactly(NumberFormatException.class, () -> hex.parse("ag"));
        byte[] parse = hex.parse("af");
        assertEquals(parse[0], (byte) 0xaf);
        byte[] bytes = new byte[1024];
        String format = hex.format(bytes);
        byte[] p = hex.parse(format);
        assertArrayEquals(bytes, p);
    }
}