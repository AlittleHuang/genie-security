package io.github.genie.security.password;

public interface PasswordDeserializer {

    ExpirablePassword deserialize(byte[] bytes);

}
