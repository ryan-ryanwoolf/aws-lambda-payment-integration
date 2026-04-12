package com.ryanwoolf.transactions;

import java.math.BigDecimal;

/**
 * Persists a new payment initiation row (idempotent create).
 */
public interface PendingTransactionRepository {

    /**
     * Inserts a row with {@code PENDING} status if {@code (partnerId, clientIdempotencyKey)} does not exist.
     *
     * @param partnerId              partner identifier (from authorizer)
     * @param clientIdempotencyKey   value from the {@code Idempotency-Key} header (trimmed)
     * @param amount                 payment amount from the request body
     * @param currency               ISO 4217 currency code from the request body (normalized)
     * @throws DuplicateTransactionException if the row already exists
     */
    void createIfAbsent(String partnerId, String clientIdempotencyKey, BigDecimal amount, String currency)
            throws DuplicateTransactionException;
}
