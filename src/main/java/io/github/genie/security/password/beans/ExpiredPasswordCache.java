package io.github.genie.security.password.beans;

public interface ExpiredPasswordCache {

    void put(String encodedPassword, long expiryAt);

    boolean exist(String encodedPassword);

}
