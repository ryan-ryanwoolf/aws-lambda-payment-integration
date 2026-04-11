package com.ryanwoolf.transactions;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ryanwoolf.authorizer.TestLambdaContext;
import org.junit.jupiter.api.Test;

import java.math.BigDecimal;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
class PaymentInitiationHandlerTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static final class RecordingRepository implements PendingTransactionRepository {
        final List<String> ids = new ArrayList<>();

        @Override
        public void createIfAbsent(String partnerId, String clientIdempotencyKey, BigDecimal amount, String currency)
                throws DuplicateTransactionException {
            String composite = TransactionIdempotencyKeys.composite(partnerId, clientIdempotencyKey);
            if (ids.contains(composite)) {
                throw new DuplicateTransactionException();
            }
            ids.add(composite);
        }
    }

    @Test
    void httpApiV2_postWithValidAuthorizerContext_returns202AndPendingStatus() throws Exception {
        Map<String, Object> event = loadJson("/http-api-v2-proxy-post-transactions.json");
        RecordingRepository repo = new RecordingRepository();
        PaymentInitiationHandler handler = new PaymentInitiationHandler(repo);

        Map<String, Object> response = handler.handleRequest(event, new TestLambdaContext());

        assertEquals(202, response.get("statusCode"));
        JsonNode body = MAPPER.readTree((String) response.get("body"));
        assertEquals("super-user#test-payment-001", body.get("transactionId").asText());
        assertEquals("super-user", body.get("partnerId").asText());
        assertEquals("Super User", body.get("partner").asText());
        assertEquals("PENDING", body.get("status").asText());
        assertEquals(0, new BigDecimal("100").compareTo(new BigDecimal(body.get("amount").asText())));
        assertEquals("EUR", body.get("currency").asText());
        assertFalse(body.get("repeat").asBoolean());
        assertEquals(1, repo.ids.size());
        assertEquals("super-user#test-payment-001", repo.ids.getFirst());
    }

    @Test
    void restApi_postWithValidAuthorizerContext_returns202() throws Exception {
        Map<String, Object> event = loadJson("/apigateway-rest-proxy-post-payments.json");
        RecordingRepository repo = new RecordingRepository();
        PaymentInitiationHandler handler = new PaymentInitiationHandler(repo);

        Map<String, Object> response = handler.handleRequest(event, new TestLambdaContext());

        assertEquals(202, response.get("statusCode"));
        JsonNode body = MAPPER.readTree((String) response.get("body"));
        assertEquals("super-user", body.get("partnerId").asText());
        assertEquals("PENDING", body.get("status").asText());
        assertEquals("super-user#test-payment-001", body.get("transactionId").asText());
        assertEquals(0, new BigDecimal("100").compareTo(new BigDecimal(body.get("amount").asText())));
        assertEquals("EUR", body.get("currency").asText());
    }

    @Test
    void duplicateIdempotency_returns409() throws Exception {
        Map<String, Object> event = loadJson("/http-api-v2-proxy-post-transactions.json");
        RecordingRepository repo = new RecordingRepository();
        PaymentInitiationHandler handler = new PaymentInitiationHandler(repo);

        assertEquals(202, handler.handleRequest(event, new TestLambdaContext()).get("statusCode"));
        Map<String, Object> second = handler.handleRequest(event, new TestLambdaContext());
        assertEquals(409, second.get("statusCode"));
        JsonNode body = MAPPER.readTree((String) second.get("body"));
        assertEquals("IDEMPOTENCY_CONFLICT", body.get("error").asText());
    }

    @Test
    void missingIdempotencyKey_returns400() throws Exception {
        Map<String, Object> event = loadJson("/http-api-v2-proxy-post-transactions.json");
        @SuppressWarnings("unchecked")
        Map<String, Object> headers = (Map<String, Object>) event.get("headers");
        headers.remove("Idempotency-Key");

        PaymentInitiationHandler handler = new PaymentInitiationHandler(new RecordingRepository());
        Map<String, Object> response = handler.handleRequest(event, new TestLambdaContext());

        assertEquals(400, response.get("statusCode"));
    }

    @Test
    void getMethod_returns405() throws Exception {
        Map<String, Object> event = loadJson("/http-api-v2-proxy-post-transactions.json");
        @SuppressWarnings("unchecked")
        Map<String, Object> requestContext = (Map<String, Object>) event.get("requestContext");
        @SuppressWarnings("unchecked")
        Map<String, Object> http = (Map<String, Object>) requestContext.get("http");
        http.put("method", "GET");

        PaymentInitiationHandler handler = new PaymentInitiationHandler(new RecordingRepository());
        Map<String, Object> response = handler.handleRequest(event, new TestLambdaContext());

        assertEquals(405, response.get("statusCode"));
        JsonNode body = MAPPER.readTree((String) response.get("body"));
        assertEquals("METHOD_NOT_ALLOWED", body.get("error").asText());
    }

    @Test
    void restApi_getMethod_returns405() throws Exception {
        Map<String, Object> event = loadJson("/apigateway-rest-proxy-post-payments.json");
        event.put("httpMethod", "GET");

        PaymentInitiationHandler handler = new PaymentInitiationHandler(new RecordingRepository());
        Map<String, Object> response = handler.handleRequest(event, new TestLambdaContext());

        assertEquals(405, response.get("statusCode"));
    }

    @Test
    void missingAuthorizerContext_returns403() throws Exception {
        Map<String, Object> event = loadJson("/http-api-v2-proxy-post-transactions.json");
        @SuppressWarnings("unchecked")
        Map<String, Object> requestContext = (Map<String, Object>) event.get("requestContext");
        requestContext.remove("authorizer");

        PaymentInitiationHandler handler = new PaymentInitiationHandler(new RecordingRepository());
        Map<String, Object> response = handler.handleRequest(event, new TestLambdaContext());

        assertEquals(403, response.get("statusCode"));
        JsonNode body = MAPPER.readTree((String) response.get("body"));
        assertEquals("FORBIDDEN", body.get("error").asText());
    }

    private static Map<String, Object> loadJson(String classpathResource) throws Exception {
        InputStream stream = PaymentInitiationHandlerTest.class.getResourceAsStream(classpathResource);
        if (stream == null) {
            throw new IllegalStateException("Missing classpath resource " + classpathResource);
        }
        try (stream) {
            return MAPPER.readValue(stream, new TypeReference<>() {});
        }
    }
}
