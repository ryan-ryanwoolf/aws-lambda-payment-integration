package com.ryanwoolf.transactions;

/**
 * Thrown when a transaction row already exists for the composite idempotency key.
 */
public final class DuplicateTransactionException extends Exception {
}
