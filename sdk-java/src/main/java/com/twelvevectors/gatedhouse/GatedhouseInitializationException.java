package com.twelvevectors.gatedhouse;

public final class GatedhouseInitializationException extends RuntimeException {

    public GatedhouseInitializationException(String message, Throwable cause) {
        super(message, cause);
    }

    public GatedhouseInitializationException(String message) {
        super(message);
    }
}
