package io.github.genie.security.password.beans;

public interface PasswordSerializer {

    byte[] serialize(TimeMarkedPassword password);

}
