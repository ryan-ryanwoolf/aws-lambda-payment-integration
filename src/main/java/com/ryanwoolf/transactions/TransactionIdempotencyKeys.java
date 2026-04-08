package com.ryanwoolf.transactions;

/**
 * Builds the composite idempotency key used as DynamoDB partition key and API
 * {@code transactionId}.
 * Format: {@code partnerId + '#' + clientSuppliedKey}. Client keys must not
 * contain {@code '#'}.
 */
public final class TransactionIdempotencyKeys {

    private TransactionIdempotencyKeys() {
    }

    // Used to build the composite idempotency key used as DynamoDB partition key
    // and API {@code transactionId}.
    public static String composite(String partnerId, String clientIdempotencyKey) {
        if (partnerId == null || partnerId.isBlank()) {
            throw new IllegalArgumentException("partnerId required");
        }
        if (clientIdempotencyKey == null) {
            throw new IllegalArgumentException("client idempotency key required");
        }
        String trimmed = clientIdempotencyKey.trim();
        if (trimmed.isEmpty()) {
            throw new IllegalArgumentException("client idempotency key required");
        }
        if (trimmed.contains("#")) {
            throw new IllegalArgumentException("idempotency key must not contain '#'");
        }
        return partnerId + "#" + trimmed;
    }
}
