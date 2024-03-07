package io.github.genie.security.password;

import java.time.Instant;

public interface ExpirablePassword {

    Instant expiry();

    String password();

}
