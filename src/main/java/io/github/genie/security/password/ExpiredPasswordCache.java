package io.github.genie.security.password;

import java.time.Instant;

public interface ExpiredPasswordCache {

    void put(String encodedPassword, Instant expiry);

    boolean exist(String encodedPassword);

}
