package io.github.genie.security.exception;

import java.security.GeneralSecurityException;

/**
 * @author HuangChengwei
 * @since 2024-03-20 10:35
 */
public class CipherExpiredException extends GeneralSecurityException {
    public CipherExpiredException(String msg) {
        super(msg);
    }
}
