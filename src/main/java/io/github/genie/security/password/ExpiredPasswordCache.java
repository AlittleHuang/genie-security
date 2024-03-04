package io.github.genie.security.password;

import java.time.Duration;

public interface ExpiredPasswordCache {

    void put(String encodedPassword, Duration timeToLife);

    boolean exist(String encodedPassword);

}
