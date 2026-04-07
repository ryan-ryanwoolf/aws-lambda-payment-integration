package com.ryanwoolf.auth;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ryanwoolf.api.ApiGatewayHeaderExtractor;
import com.ryanwoolf.authorizer.model.PartnerRecord;
import com.ryanwoolf.authorizer.service.PartnerLookup;
import com.ryanwoolf.authorizer.service.PartnerLookupService;

import java.util.HashMap;
import java.util.Map;

/**
 * Public REST API endpoint: validates {@code x-api-key} + {@code x-partner-id}
 * (Argon2 in DynamoDB)
 * and returns a short-lived JWT for {@link JwtPolicyAuthorizerHandler}.
 * <p>
 * Handler: {@code com.ryanwoolf.auth.PartnerTokenIssuerHandler}
 */
public class PartnerTokenIssuerHandler implements RequestHandler<Map<String, Object>, Map<String, Object>> {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final PartnerLookup partnerLookup;
    /**
     * Lazily created unless injected in tests (avoids Secrets Manager calls during
     * Lambda INIT).
     */
    private volatile JwtTokenService jwtTokenService;
    private final boolean jwtInjected;

    public PartnerTokenIssuerHandler() {
        this.partnerLookup = new PartnerLookupService();
        this.jwtTokenService = null;
        this.jwtInjected = false;
    }

    PartnerTokenIssuerHandler(PartnerLookup partnerLookup, JwtTokenService jwtTokenService) {
        this.partnerLookup = partnerLookup;
        this.jwtTokenService = jwtTokenService;
        this.jwtInjected = true;
    }

    private JwtTokenService jwt() {
        if (jwtInjected) {
            return jwtTokenService;
        }
        JwtTokenService j = jwtTokenService;
        if (j == null) {
            synchronized (this) {
                j = jwtTokenService;
                if (j == null) {
                    jwtTokenService = JwtTokenService.forTokenIssuer();
                    j = jwtTokenService;
                }
            }
        }
        return j;
    }

    @Override
    public Map<String, Object> handleRequest(Map<String, Object> event, Context context) {
        try {
            String method = stringVal(event.get("httpMethod"));
            validatePostRequest(method);
            String apiKey = ApiGatewayHeaderExtractor.getHeader(event, "x-api-key");
            String partnerId = ApiGatewayHeaderExtractor.getHeader(event, "x-partner-id");
            validateapiKeyAndPartnerIdPresent(apiKey, partnerId);
            PartnerRecord partner = partnerLookup.findByPartnerIdAndApiKey(partnerId, apiKey);
            validatePartnerExists(partner);
            String token = jwt().createAccessToken(partnerId, partner.partner());

            Map<String, Object> body = new HashMap<>();
            body.put("access_token", token);
            body.put("token_type", "Bearer");
            body.put("expires_in", jwt().ttlSeconds());

            context.getLogger().log("Issued JWT for partnerId=" + partnerId);
            return jsonResponse(200, body);
        } catch (TokenIssuerUnauthorizedException e) {
            context.getLogger().log("Token issuer unauthorized: " + e.getMessage());
            return jsonResponse(401, Map.of(
                    "error", "UNAUTHORIZED",
                    "message", e.getMessage()));
        } catch (IllegalArgumentException e) {
            context.getLogger().log("Token issuer error: " + e.getClass().getName() + ": " + e.getMessage());
            return jsonResponse(400, Map.of(
                    "error", "BAD_REQUEST",
                    "message", e.getMessage()));
        } catch (Exception e) {
            context.getLogger().log("Token issuer error: " + e.getClass().getName() + ": " + e.getMessage());
            return jsonResponse(500, Map.of("error", "INTERNAL_ERROR"));
        }
    }

    private static void validatePartnerExists(PartnerRecord partner) {
        if (partner == null || !partner.enabled()) {
            throw new TokenIssuerUnauthorizedException("Invalid credentials or partner disabled");
        }
    }

    private static void validateapiKeyAndPartnerIdPresent(String apiKey, String partnerId) {
        if (apiKey == null || apiKey.isBlank() || partnerId == null || partnerId.isBlank()) {
            throw new TokenIssuerUnauthorizedException("Missing x-api-key or x-partner-id");
        }
    }

    private static void validatePostRequest(String method) {
        if (method != null && !"POST".equalsIgnoreCase(method)) {
            throw new IllegalArgumentException("Only POST method is supported");
        }
    }

    private static String stringVal(Object o) {
        return o == null ? null : String.valueOf(o);
    }

    private static Map<String, Object> jsonResponse(int statusCode, Object body) {
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
