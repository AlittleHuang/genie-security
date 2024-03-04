package io.github.genie.security.format;

import org.jetbrains.annotations.NotNull;

import java.util.Base64;

public class Base64Format implements BinaryFormat {

    public static final Base64Format BASE_64_FORMAT = new Base64Format(Base64.getEncoder(), Base64.getDecoder());
    private final Base64.Encoder encoder;
    private final Base64.Decoder decoder;

    public static Base64Format of() {
        return BASE_64_FORMAT;
    }

    public Base64Format(Base64.Encoder encoder, Base64.Decoder decoder) {
        this.encoder = encoder;
        this.decoder = decoder;
    }


    @Override
    public @NotNull String format(byte @NotNull [] raw) {
        return encoder.encodeToString(raw);
    }

    @Override
    public byte @NotNull [] parse(@NotNull String base64) throws IllegalArgumentException {
        try {
            return decoder.decode(base64);
        } catch (Exception e) {
            throw new IllegalArgumentException(e);
        }
    }
}
