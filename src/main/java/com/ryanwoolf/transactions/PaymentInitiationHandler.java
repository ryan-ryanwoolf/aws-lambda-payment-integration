package com.ryanwoolf.transactions;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.ryanwoolf.api.ApiGatewayHeaderExtractor;

import java.util.HashMap;
import java.util.Map;

/**
 * Payment initiation Lambda (REST API proxy or HTTP API v2 proxy).
 * Partner identity comes only from the API Gateway authorizer context (never from the body).
 * Requires header {@code Idempotency-Key}; the composite {@code partnerId#key} is stored in DynamoDB
 * and returned as {@code transactionId}.
 * <p>
 * Handler: {@code com.ryanwoolf.transactions.PaymentInitiationHandler}
 */
public class PaymentInitiationHandler implements RequestHandler<Map<String, Object>, Map<String, Object>> {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final PendingTransactionRepository pendingTransactions;

    public PaymentInitiationHandler() {
        this(new DynamoDbPendingTransactionRepository());
    }

    PaymentInitiationHandler(PendingTransactionRepository pendingTransactions) {
        this.pendingTransactions = pendingTransactions;
    }

    @Override
    public Map<String, Object> handleRequest(Map<String, Object> event, Context context) {
        try {
            String method = extractHttpMethod(event);
            if (method != null && !"POST".equalsIgnoreCase(method)) {
                return jsonResponse(405, Map.of(
                        "error", "METHOD_NOT_ALLOWED",
                        "message", "Only POST is supported"));
            }

            AuthorizerLambdaContext auth = AuthorizerLambdaContext.fromEvent(event);
            if (auth == null || !auth.isEffectivelyAuthorized()) {
                return jsonResponse(403, Map.of(
                        "error", "FORBIDDEN",
                        "message", "Missing or invalid authorizer context"));
            }

            String partnerId = auth.partnerId();
            if (partnerId == null || partnerId.isBlank()) {
                return jsonResponse(403, Map.of(
                        "error", "FORBIDDEN",
                        "message", "partnerId missing from authorizer context"));
            }

            String clientIdempotencyKey = ApiGatewayHeaderExtractor.getHeader(event, "Idempotency-Key");
            if (clientIdempotencyKey == null || clientIdempotencyKey.isBlank()) {
                return jsonResponse(400, Map.of(
                        "error", "BAD_REQUEST",
                        "message", "Missing Idempotency-Key header"));
            }

            final String compositeKey;
            try {
                compositeKey = TransactionIdempotencyKeys.composite(partnerId, clientIdempotencyKey);
            } catch (IllegalArgumentException e) {
                return jsonResponse(400, Map.of(
                        "error", "BAD_REQUEST",
                        "message", e.getMessage()));
            }

            try {
                pendingTransactions.createIfAbsent(compositeKey, partnerId);
            } catch (DuplicateTransactionException e) {
                return jsonResponse(409, Map.of(
                        "error", "IDEMPOTENCY_CONFLICT",
                        "message", "A transaction already exists for this partner and Idempotency-Key"));
            }

            ObjectNode body = MAPPER.createObjectNode();
            body.put("transactionId", compositeKey);
            body.put("partnerId", partnerId);
            if (auth.partnerDisplayName() != null && !auth.partnerDisplayName().isBlank()) {
                body.put("partner", auth.partnerDisplayName());
            }
            body.put("status", DynamoDbPendingTransactionRepository.STATUS_PENDING);
            body.put("repeat", false);

            context.getLogger().log(
                    "Payment initiation accepted for partnerId=" + partnerId + ", transactionId=" + compositeKey);

            return jsonResponse(202, body);
        } catch (Exception e) {
            context.getLogger().log("Payment initiation error: " + e.getMessage());
            try {
                return jsonResponse(500, Map.of("error", "INTERNAL_ERROR"));
            } catch (Exception ex) {
                throw new IllegalStateException(ex);
            }
        }
    }

    /**
     * REST API proxy uses top-level {@code httpMethod}. HTTP API v2 uses {@code requestContext.http.method}.
     */
    private static String extractHttpMethod(Map<String, Object> event) {
        Object top = event.get("httpMethod");
        if (top != null) {
            return String.valueOf(top);
        }
        Object requestContext = event.get("requestContext");
        if (!(requestContext instanceof Map<?, ?> rc)) {
            return null;
        }
        Object http = rc.get("http");
        if (!(http instanceof Map<?, ?> h)) {
            return null;
        }
        Object m = h.get("method");
        return m != null ? String.valueOf(m) : null;
    }

    private static Map<String, Object> jsonResponse(int statusCode, Object body) throws Exception {
        Map<String, String> headers = Map.of("content-type", "application/json");
        Map<String, Object> response = new HashMap<>();
        response.put("statusCode", statusCode);
        response.put("headers", headers);
        response.put("body", MAPPER.writeValueAsString(body));
        return response;
    }

    /**
     * REST API: flat string map under {@code requestContext.authorizer}.
     * HTTP API v2: nested under {@code requestContext.authorizer.lambda}.
     */
    private static final class AuthorizerLambdaContext {
        private final String partnerId;
        private final String partnerDisplayName;
        private final Object authorizedRaw;

        private AuthorizerLambdaContext(String partnerId, String partnerDisplayName, Object authorizedRaw) {
            this.partnerId = partnerId;
            this.partnerDisplayName = partnerDisplayName;
            this.authorizedRaw = authorizedRaw;
        }

        static AuthorizerLambdaContext fromEvent(Map<String, Object> event) {
            Object requestContext = event.get("requestContext");
            if (!(requestContext instanceof Map<?, ?> rc)) {
                return null;
            }
            Object authorizer = rc.get("authorizer");
            if (!(authorizer instanceof Map<?, ?> au)) {
                return null;
            }

            Map<?, ?> source = au;
            Object lambda = au.get("lambda");
            if (lambda instanceof Map<?, ?> lam) {
                source = lam;
            }

            String partnerId = stringValue(source.get("partnerId"));
            String partner = stringValue(source.get("partner"));
            Object authorized = source.get("authorized");
            return new AuthorizerLambdaContext(partnerId, partner, authorized);
        }

        private static String stringValue(Object o) {
            return o == null ? null : String.valueOf(o);
        }

        String partnerId() {
            return partnerId;
        }

        String partnerDisplayName() {
            return partnerDisplayName;
        }

        boolean isEffectivelyAuthorized() {
            if (authorizedRaw instanceof Boolean b) {
                return b;
            }
            if (authorizedRaw == null) {
                return partnerId != null && !partnerId.isBlank();
            }
            return "true".equalsIgnoreCase(String.valueOf(authorizedRaw));
        }
    }
}
