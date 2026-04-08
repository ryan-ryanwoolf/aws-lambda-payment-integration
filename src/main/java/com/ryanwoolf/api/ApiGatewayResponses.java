package com.ryanwoolf.api;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.HashMap;
import java.util.Map;

/**
 * Shared API Gateway proxy response factory.
 */
public final class ApiGatewayResponses {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private ApiGatewayResponses() {
    }

    public static Map<String, Object> jsonResponse(int statusCode, Object body) {
        Map<String, String> headers = new HashMap<>();
        headers.put("content-type", "application/json");

        Map<String, Object> response = new HashMap<>();
        response.put("statusCode", statusCode);
        response.put("headers", headers);
        try {
            response.put("body", MAPPER.writeValueAsString(body));
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Failed to serialize response", e);
        }
        return response;
    }
}
