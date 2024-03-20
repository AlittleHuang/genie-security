package io.github.genie.security.format;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrowsExactly;

/**
 * @author HuangChengwei
 * @since 2024-03-20 11:30
 */
class HexFormatTest {

    @Test
    void parse() {
        assertThrowsExactly(IllegalArgumentException.class, () -> HexFormat.of().parse("a"));
        assertThrowsExactly(NumberFormatException.class, () -> HexFormat.of().parse("ag"));
        byte[] parse = HexFormat.of().parse("af");
        assertEquals(parse[0], (byte) 0xaf);
    }
}