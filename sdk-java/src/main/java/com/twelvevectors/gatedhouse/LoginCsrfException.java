package com.twelvevectors.gatedhouse;

/**
 * Thrown by {@link LoginFlow#completeLogin} when the callback was not initiated by this browser —
 * no pending-flow cookie, a tampered cookie, or (downstream) a PKCE verifier that doesn't match the
 * code's challenge. The app must treat this as a rejected login and must NOT adopt any identity.
 */
public final class LoginCsrfException extends RuntimeException {
    public LoginCsrfException(String message) {
        super(message);
    }
}
