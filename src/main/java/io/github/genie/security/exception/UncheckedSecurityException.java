package io.github.genie.security.exception;

import java.security.GeneralSecurityException;

/**
 * @author HuangChengwei
 * @since 2024-03-20 10:08
 */
public class UncheckedSecurityException extends RuntimeException {
    public UncheckedSecurityException(GeneralSecurityException cause) {
        super(cause);
    }
}
