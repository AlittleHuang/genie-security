package io.github.genie.security.format;

import org.jetbrains.annotations.NotNull;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class HexFormat implements BinaryFormat {
    private final byte[] digits;

    HexFormat(byte[] digits) {
        this.digits = digits;
    }

    public static HexFormat of() {
        return of(true);
    }

    public static HexFormat of(boolean lowerCase) {
        return lowerCase ? HEX_BINARY_FORMAT_LOWER : HEX_BINARY_FORMAT_UPPER;
    }

    @Override
    public @NotNull String format(byte @NotNull [] input) {
        int l = input.length, i = 0, j = 0;
        byte[] out = new byte[l << 1];
        while (i < l) {
            out[j++] = digits[(0xf0 & input[i]) >>> 4];
            out[j++] = digits[0x0f & input[i++]];
        }
        return new String(out, StandardCharsets.US_ASCII);
    }

    @Override
    public byte @NotNull [] parse(@NotNull String hex) throws IllegalArgumentException {
        if ((hex.length() & 1) != 0) {
            throw new IllegalArgumentException("string length not even: " + hex.length());
        }
        hex = hex.toUpperCase();
        int length = hex.length() >> 1;
        byte[] dst = new byte[length];
        for (int i = 0; i < length; i++) {
            int pos = i << 1;
            dst[i] = (byte) (fromHexDigit(hex.charAt(pos)) << 4 | fromHexDigit(hex.charAt(pos + 1)));
        }
        return dst;
    }

    public static int fromHexDigit(int ch) {
        if ((ch >>> 7) == 0 && VALUES[ch] >= 0) {
            return VALUES[ch];
        }
        throw new NumberFormatException("not a hexadecimal digit: \"" + (char) ch + "\" = " + ch);
    }

    private static final byte[] DIGITS_LOWER = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
    private static final byte[] DIGITS_UPPER = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
    private static final byte[] VALUES = new byte[128];

    static {
        Arrays.fill(VALUES, (byte) -1);
        for (byte i = 0; i < DIGITS_LOWER.length; i++) {
            VALUES[DIGITS_LOWER[i]] = VALUES[DIGITS_UPPER[i]] = i;
        }
    }

    public static final HexFormat HEX_BINARY_FORMAT_LOWER = new HexFormat(DIGITS_LOWER);
    public static final HexFormat HEX_BINARY_FORMAT_UPPER = new HexFormat(DIGITS_UPPER);

}
