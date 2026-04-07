package com.ryanwoolf.auth;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MethodArnPaymentMatcherTest {

    private static final String VALID =
            "arn:aws:execute-api:eu-west-1:123456789012:abc123def/production/POST/payments";

    @Test
    void matches_postPayments() {
        MethodArnPaymentMatcher matcher = new MethodArnPaymentMatcher("POST", "payments");
        assertTrue(matcher.matchesPaymentInitiation(VALID));
    }

    @Test
    void rejects_wrongVerb() {
        MethodArnPaymentMatcher matcher = new MethodArnPaymentMatcher("POST", "payments");
        String getArn = VALID.replace("/POST/", "/GET/");
        assertFalse(matcher.matchesPaymentInitiation(getArn));
    }

    @Test
    void rejects_wrongResource() {
        MethodArnPaymentMatcher matcher = new MethodArnPaymentMatcher("POST", "payments");
        assertFalse(matcher.matchesPaymentInitiation(VALID.replace("payments", "auth")));
    }
}
