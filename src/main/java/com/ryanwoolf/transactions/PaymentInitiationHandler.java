package com.ryanwoolf.transactions;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.ryanwoolf.api.ApiGatewayResponses;
import com.ryanwoolf.api.ApiGatewayHeaderExtractor;
import com.ryanwoolf.api.LambdaExceptionMapper;

import java.util.List;
import java.util.Map;

/**
 * Payment initiation Lambda (REST API proxy or HTTP API v2 proxy).
 * Partner identity comes only from the API Gateway authorizer context (never
 * from the body).
 * Requires header {@code Idempotency-Key}; the composite {@code partnerId#key}
 * is stored in DynamoDB
 * and returned as {@code transactionId}.
 * <p>
 * Handler: {@code com.ryanwoolf.transactions.PaymentInitiationHandler}
 */
public class PaymentInitiationHandler implements RequestHandler<Map<String, Object>, Map<String, Object>> {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final List<LambdaExceptionMapper.ExceptionRule> ERROR_RULES = List.of(
            LambdaExceptionMapper.ExceptionRule.withExceptionMessage(
                    MethodNotAllowedException.class, 405, "METHOD_NOT_ALLOWED"),
            LambdaExceptionMapper.ExceptionRule.withExceptionMessage(
                    IllegalArgumentException.class, 400, "BAD_REQUEST"),
            LambdaExceptionMapper.ExceptionRule.withFixedMessage(
                    DuplicateTransactionException.class,
                    409,
                    "IDEMPOTENCY_CONFLICT",
                    "A transaction already exists for this partner and Idempotency-Key"),
            LambdaExceptionMapper.ExceptionRule.withExceptionMessage(
                    AuthorizerDeniedException.class, 403, "FORBIDDEN"));
    private static final LambdaExceptionMapper.ExceptionRule DEFAULT_ERROR_RULE = LambdaExceptionMapper.ExceptionRule
            .withoutMessage(Exception.class, 500, "INTERNAL_ERROR");

    private final PendingTransactionRepository pendingTransactions;

    public PaymentInitiationHandler() {
        this(new DynamoDbPendingTransactionRepository());
    }

    PaymentInitiationHandler(PendingTransactionRepository pendingTransactions) {
        this.pendingTransactions = pendingTransactions;
    }

    // Used to handle the payment initiation request
    @Override
    public Map<String, Object> handleRequest(Map<String, Object> event, Context context) {
        try {
            String method = extractHttpMethod(event);
            validateRequestMethod(method);

            AuthorizerLambdaContext auth = AuthorizerLambdaContext.fromEvent(event);
            validateRequestEffectivelyDenied(auth);

            String partnerId = auth.partnerId();
            validatePartnerIdInSecurityContext(partnerId);
            String clientIdempotencyKey = ApiGatewayHeaderExtractor.getHeader(event, "Idempotency-Key");
            validateIdempotencyKeyPresent(clientIdempotencyKey);

            final String compositeKey;

            // Used to create the composite key for the idempotency key
            compositeKey = TransactionIdempotencyKeys.composite(partnerId, clientIdempotencyKey);
            pendingTransactions.createIfAbsent(compositeKey, partnerId);

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

            return ApiGatewayResponses.jsonResponse(202, body);
        } catch (Exception e) {
            return LambdaExceptionMapper.map(
                    e,
                    context,
                    "Payment initiation error: ",
                    ERROR_RULES,
                    DEFAULT_ERROR_RULE);
        }
    }

    // Used to validate that the idempotency key is present and not blank
    private static void validateIdempotencyKeyPresent(String clientIdempotencyKey) {
        if (clientIdempotencyKey == null || clientIdempotencyKey.isBlank()) {
            throw new IllegalArgumentException("Idempotency Key header is required and cannot be blank");
        }
    }

    // Used to validate that the partner id is present and not blank
    private static void validatePartnerIdInSecurityContext(String partnerId) {
        if (partnerId == null || partnerId.isBlank()) {
            throw new AuthorizerDeniedException("Unauthorized: missing partnerId in authorizer context");
        }
    }

    // Used to validate that the request is not effectively denied
    private static void validateRequestEffectivelyDenied(AuthorizerLambdaContext auth) {
        if (auth == null || !auth.isEffectivelyAuthorized()) {
            throw new AuthorizerDeniedException("Unauthorized: missing or invalid authorizer context");
        }
    }

    // Used to validate that the request method is POST
    private static void validateRequestMethod(String method) {
        if (method != null && !"POST".equalsIgnoreCase(method)) {
            throw new MethodNotAllowedException("Only POST is supported");
        }
    }

    /**
     * REST API proxy uses top-level {@code httpMethod}. HTTP API v2 uses
     * {@code requestContext.http.method}.
     */
    // Used to extract the HTTP method from the event
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

    /**
     * REST API: flat string map under {@code requestContext.authorizer}.
     * HTTP API v2: nested under {@code requestContext.authorizer.lambda}.
     */
    // Used to extract the authorizer lambda context from the event
    private static final class AuthorizerLambdaContext {
        private final String partnerId;
        private final String partnerDisplayName;
        private final Object authorizedRaw;

        private AuthorizerLambdaContext(String partnerId, String partnerDisplayName, Object authorizedRaw) {
            this.partnerId = partnerId;
            this.partnerDisplayName = partnerDisplayName;
            this.authorizedRaw = authorizedRaw;
        }

        // Used to extract the authorizer lambda context from the event
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

        // Used to check if the authorized context comes through with true value
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
