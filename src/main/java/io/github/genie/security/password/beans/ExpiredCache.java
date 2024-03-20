package io.github.genie.security.password.beans;

public interface ExpiredCache {

    void put(String key, long expiryAt);

    boolean exist(String key);

}
