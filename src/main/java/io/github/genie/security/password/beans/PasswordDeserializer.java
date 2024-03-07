package io.github.genie.security.password.beans;

public interface PasswordDeserializer {

    TimeMarkedPassword deserialize(byte[] bytes);

}
