package com.ryanwoolf.transactions;

/**
 * Request method is not supported for this endpoint.
 * Handled by {@link PaymentInitiationHandler} as HTTP 405.
 */
public final class MethodNotAllowedException extends RuntimeException {

    // Used to create a new MethodNotAllowedException with a message
    public MethodNotAllowedException(String message) {
        super(message);
    }
}
