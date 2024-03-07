package io.github.genie.security.format;

import java.security.GeneralSecurityException;

public interface Encryptor {

    byte[] encrypt(byte[] raw) throws GeneralSecurityException;

}
