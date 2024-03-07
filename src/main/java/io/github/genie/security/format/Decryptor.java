package io.github.genie.security.format;

import java.security.GeneralSecurityException;

public interface Decryptor {

    byte[] decrypt(byte[] coded) throws GeneralSecurityException;

}
