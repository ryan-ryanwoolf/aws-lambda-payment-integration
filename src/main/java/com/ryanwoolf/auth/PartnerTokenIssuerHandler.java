package com.ryanwoolf.auth;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.ryanwoolf.api.ApiGatewayResponses;
import com.ryanwoolf.api.ApiGatewayHeaderExtractor;
import com.ryanwoolf.api.LambdaExceptionMapper;
import com.ryanwoolf.authorizer.model.PartnerRecord;
import com.ryanwoolf.authorizer.service.PartnerLookup;
import com.ryanwoolf.authorizer.service.PartnerLookupService;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Public REST API endpoint: validates {@code x-api-key} + {@code x-partner-id}
 * (Argon2 hash stored in Postgres)
 * and returns a short-lived JWT for {@link JwtPolicyAuthorizerHandler}.
 * <p>
 * Handler: {@code com.ryanwoolf.auth.PartnerTokenIssuerHandler}
 */
public class PartnerTokenIssuerHandler implements RequestHandler<Map<String, Object>, Map<String, Object>> {
    private static final List<LambdaExceptionMapper.ExceptionRule> ERROR_RULES = List.of(
            LambdaExceptionMapper.ExceptionRule.withExceptionMessage(
                    TokenIssuerUnauthorizedException.class, 401, "UNAUTHORIZED"),
            LambdaExceptionMapper.ExceptionRule.withExceptionMessage(
                    IllegalArgumentException.class, 400, "BAD_REQUEST")
    );
    private static final LambdaExceptionMapper.ExceptionRule DEFAULT_ERROR_RULE =
            LambdaExceptionMapper.ExceptionRule.withoutMessage(Exception.class, 500, "INTERNAL_ERROR");

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

    // Used by token issuer to create JWTs for the authorizer to verify.
    // Lazily initialized to avoid Secrets Manager calls during Lambda INIT.
    // Note this is specifically to handle the cold start vs warm start scenario
    // where the Lambda may be invoked before the Secrets Manager client can retrieve the PEM for the JWT signing key.
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

    // This handles issuing a JWT for a partner after validating x-api-key and
    // x-partner-id against Postgres-backed partner credentials.
    @Override
    public Map<String, Object> handleRequest(Map<String, Object> event, Context context) {
        long requestStartNanos = System.nanoTime();
        try {
            long validationStartNanos = System.nanoTime();
            logStart(context, "request_validation");
            String method = stringVal(event.get("httpMethod"));
            validatePostRequest(method);
            String apiKey = ApiGatewayHeaderExtractor.getHeader(event, "x-api-key");
            String partnerId = ApiGatewayHeaderExtractor.getHeader(event, "x-partner-id");
            validateApiKeyAndPartnerIdPresent(apiKey, partnerId);
            logEnd(context, "request_validation", validationStartNanos);

            long lookupStartNanos = System.nanoTime();
            logStart(context, "partner_lookup");
            PartnerRecord partner = partnerLookup.findByPartnerIdAndApiKey(partnerId, apiKey);
            validatePartnerExists(partner);
            logEnd(context, "partner_lookup", lookupStartNanos);

            long jwtInitStartNanos = System.nanoTime();
            logStart(context, "jwt_service_init");
            JwtTokenService jwtService = jwt();
            logEnd(context, "jwt_service_init", jwtInitStartNanos);

            long tokenSignStartNanos = System.nanoTime();
            logStart(context, "token_signing");
            String token = jwtService.createAccessToken(partnerId, partner.partner());
            logEnd(context, "token_signing", tokenSignStartNanos);

            Map<String, Object> body = new HashMap<>();
            body.put("access_token", token);
            body.put("token_type", "Bearer");
            body.put("expires_in", jwtService.ttlSeconds());

            context.getLogger().log("Issued JWT for partnerId=" + partnerId);
            context.getLogger().log("Timing: operation=token_issue_total status=end elapsedMs="
                    + elapsedMillis(requestStartNanos));
            return ApiGatewayResponses.jsonResponse(200, body);
        } catch (Exception e) {
            context.getLogger().log("Timing: operation=token_issue_total status=end elapsedMs="
                    + elapsedMillis(requestStartNanos));
            return LambdaExceptionMapper.map(
                    e,
                    context,
                    "Token issuer error: ",
                    ERROR_RULES,
                    DEFAULT_ERROR_RULE);
        }
    }

    // Used to validate that the partner exists and is enabled
    private static void validatePartnerExists(PartnerRecord partner) {
        if (partner == null || !partner.enabled()) {
            throw new TokenIssuerUnauthorizedException("Invalid credentials or partner disabled");
        }
    }

    // Validates that the api key and partner id are present in the request.
    private static void validateApiKeyAndPartnerIdPresent(String apiKey, String partnerId) {
        if (apiKey == null || apiKey.isBlank() || partnerId == null || partnerId.isBlank()) {
            throw new TokenIssuerUnauthorizedException("Missing x-api-key or x-partner-id");
        }
    }

    // Used to validate that the HTTP method is POST, as this endpoint should only support POST requests for token issuance.
    private static void validatePostRequest(String method) {
        if (method != null && !"POST".equalsIgnoreCase(method)) {
            throw new IllegalArgumentException("Only POST method is supported");
        }
    }

    private static String stringVal(Object o) {
        return o == null ? null : String.valueOf(o);
    }

    private static void logStart(Context context, String operation) {
        context.getLogger().log("Timing: operation=" + operation + " status=start");
    }

    private static void logEnd(Context context, String operation, long startedAtNanos) {
        context.getLogger().log("Timing: operation=" + operation + " status=end elapsedMs="
                + elapsedMillis(startedAtNanos));
    }

    private static long elapsedMillis(long startedAtNanos) {
        return (System.nanoTime() - startedAtNanos) / 1_000_000L;
    }

}
