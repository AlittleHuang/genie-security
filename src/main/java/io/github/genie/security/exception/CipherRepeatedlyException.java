package io.github.genie.security.exception;

import java.security.GeneralSecurityException;

/**
 * @author HuangChengwei
 * @since 2024-03-20 10:33
 */
public class CipherRepeatedlyException extends GeneralSecurityException {
    public CipherRepeatedlyException(String message) {
        super(message);
    }
}
