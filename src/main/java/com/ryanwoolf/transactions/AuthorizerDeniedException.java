package com.ryanwoolf.transactions;

/**
 * Request is denied because API Gateway authorizer context is missing or invalid.
 * Handled by {@link PaymentInitiationHandler} as HTTP 403.
 */
public final class AuthorizerDeniedException extends RuntimeException {

    public AuthorizerDeniedException(String message) {
        super(message);
    }
}
