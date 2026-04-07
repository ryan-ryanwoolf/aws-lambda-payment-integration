package com.ryanwoolf.transactions;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class TransactionIdempotencyKeysTest {

    @Test
    void composite_joinsPartnerAndClientKey() {
        assertEquals("acme#order-001", TransactionIdempotencyKeys.composite("acme", "order-001"));
        assertEquals("acme#order-001", TransactionIdempotencyKeys.composite("acme", "  order-001  "));
    }

    @Test
    void rejects_hashInClientKey() {
        assertThrows(IllegalArgumentException.class, () ->
                TransactionIdempotencyKeys.composite("acme", "bad#key"));
    }
}
