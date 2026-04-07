package com.ryanwoolf.transactions;

/**
 * Persists a new payment initiation row (idempotent create).
 */
public interface PendingTransactionRepository {

    /**
     * Inserts a row with {@code PENDING} status if the partition key does not exist.
     *
     * @param compositeIdempotencyKey partner-scoped key ({@link TransactionIdempotencyKeys#composite})
     * @param partnerId               partner identifier (from authorizer)
     * @throws DuplicateTransactionException if the row already exists
     */
    void createIfAbsent(String compositeIdempotencyKey, String partnerId) throws DuplicateTransactionException;
}
