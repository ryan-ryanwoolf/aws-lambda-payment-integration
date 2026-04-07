package com.ryanwoolf.auth;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ryanwoolf.authorizer.TestLambdaContext;
import com.ryanwoolf.authorizer.model.PartnerRecord;
import com.ryanwoolf.authorizer.service.PartnerLookup;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PartnerTokenIssuerHandlerTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static JwtTokenService testJwt() {
        return JwtTestKeys.jwtService(JwtTestKeys.rsa2048(), 600);
    }

    @Test
    void missingHeaders_returns401() throws Exception {
        PartnerLookup lookup = (pid, key) -> null;
        PartnerTokenIssuerHandler handler = new PartnerTokenIssuerHandler(lookup, testJwt());
        Map<String, Object> event = new HashMap<>();
        event.put("httpMethod", "POST");
        event.put("headers", Map.of());

        Map<String, Object> response = handler.handleRequest(event, new TestLambdaContext());
        assertEquals(401, response.get("statusCode"));
    }

    @Test
    void validCredentials_returnsAccessToken() throws Exception {
        PartnerLookup lookup = (pid, key) -> new PartnerRecord("Super User", true);
        PartnerTokenIssuerHandler handler = new PartnerTokenIssuerHandler(lookup, testJwt());

        Map<String, Object> headers = new HashMap<>();
        headers.put("x-api-key", "secret-key");
        headers.put("x-partner-id", "super-user");
        Map<String, Object> event = new HashMap<>();
        event.put("httpMethod", "POST");
        event.put("headers", headers);

        Map<String, Object> response = handler.handleRequest(event, new TestLambdaContext());
        assertEquals(200, response.get("statusCode"));
        JsonNode body = MAPPER.readTree((String) response.get("body"));
        assertNotNull(body.get("access_token"));
        assertTrue(body.get("access_token").asText().length() > 20);
        assertEquals("Bearer", body.get("token_type").asText());
        assertEquals(600, body.get("expires_in").asInt());
    }
}
