package com.ryanwoolf.auth;

/**
 * API key / partner validation failed, or required headers are missing.
 * Handled by {@link PartnerTokenIssuerHandler} as HTTP 401.
 */
public final class TokenIssuerUnauthorizedException extends RuntimeException {

    public TokenIssuerUnauthorizedException(String message) {
        super(message);
    }
}
