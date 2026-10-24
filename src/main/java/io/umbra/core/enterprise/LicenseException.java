package io.umbra.core.enterprise;

/** Raised when a required enterprise license is missing, expired or invalid. */
public class LicenseException extends RuntimeException {

    public LicenseException(String message) {
        super(message);
    }

    public LicenseException(String message, Throwable cause) {
        super(message, cause);
    }
}
