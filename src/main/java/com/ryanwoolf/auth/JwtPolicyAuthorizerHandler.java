package com.ryanwoolf.auth;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.auth0.jwt.interfaces.DecodedJWT;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * API Gateway <strong>REST API</strong> Lambda authorizer ({@code TOKEN} type).
 * Verifies JWT from {@code Authorization: Bearer ...} and returns an IAM policy
 * that allows
 * {@code execute-api:Invoke} only for the incoming {@code methodArn} when it
 * matches the
 * configured payment initiation route ({@link MethodArnPaymentMatcher}).
 * <p>
 * Handler: {@code com.ryanwoolf.auth.JwtPolicyAuthorizerHandler}
 */
public class JwtPolicyAuthorizerHandler implements RequestHandler<Map<String, Object>, Map<String, Object>> {

    private volatile JwtTokenService jwtTokenService;
    private final MethodArnPaymentMatcher paymentMatcher;
    private final boolean jwtInjected;

    public JwtPolicyAuthorizerHandler() {
        this.jwtTokenService = null;
        this.paymentMatcher = new MethodArnPaymentMatcher();
        this.jwtInjected = false;
    }

    JwtPolicyAuthorizerHandler(JwtTokenService jwtTokenService, MethodArnPaymentMatcher paymentMatcher) {
        this.jwtTokenService = jwtTokenService;
        this.paymentMatcher = paymentMatcher;
        this.jwtInjected = true;
    }

    // Used to get the JwtTokenService instance, either from the injected instance or by creating a new one if it is not already initialized
    private JwtTokenService jwt() {
        if (jwtInjected) {
            return jwtTokenService;
        }
        JwtTokenService j = jwtTokenService;
        if (j == null) {
            synchronized (this) {
                j = jwtTokenService;
                if (j == null) {
                    jwtTokenService = JwtTokenService.forAuthorizer();
                    j = jwtTokenService;
                }
            }
        }
        return j;
    }

    // Used as an authorized that denies access to the guarded api unless the JWT is
    // valid and the methodArn matches the configured payment initiation route
    @Override
    public Map<String, Object> handleRequest(Map<String, Object> event, Context context) {
        String methodArn = stringVal(event.get("methodArn"));
        String rawToken = stringVal(event.get("authorizationToken"));
        String cleanToken = null;
        if (rawToken != null) {
            cleanToken = stripBearer(rawToken);
        }
        Map<String, Object> validateInputsDenyPolicyResponse = validateRequestMetadata(context, methodArn, rawToken,
                cleanToken);
        // If the request metadata is invalid, return a deny policy
        if (validateInputsDenyPolicyResponse != null)
            return validateInputsDenyPolicyResponse;

        try {
            DecodedJWT jwt = jwt().verify(cleanToken);
            String partnerId = jwt.getClaim(JwtTokenService.CLAIM_PARTNER_ID).asString();
            if (partnerId == null || partnerId.isBlank()) {
                partnerId = jwt.getSubject();
            }
            String partner = jwt.getClaim(JwtTokenService.CLAIM_PARTNER).asString();

            Map<String, Object> response = new HashMap<>();
            response.put("principalId", "partner|" + partnerId);
            response.put("policyDocument", allowPolicyDocument(methodArn));

            Map<String, Object> ctx = new HashMap<>();
            ctx.put("partnerId", partnerId);
            if (partner != null) {
                ctx.put("partner", partner);
            }
            ctx.put("authorized", "true");
            response.put("context", ctx);

            context.getLogger().log("Authorizer allowed for partnerId=" + partnerId);
            // success pathway should return a document policy with an allow for the
            // specific api that is being authorized
            return response;
        } catch (Exception e) {
            context.getLogger().log("Authorizer denied: invalid token — " + e.getMessage());
            return denyPolicy("invalid-token", methodArn);
        }
    }

    // Used to validate the presence of required fields and basic formatting before
    // attempting JWT verification, to allow for more specific logging and deny
    // policies
    private Map<String, Object> validateRequestMetadata(Context context, String methodArn, String rawToken,
            String cleanToken) {
        if (methodArn == null || rawToken == null) {
            context.getLogger().log("Authorizer denied: missing methodArn or authorizationToken");
            return denyPolicy("anonymous", methodArn);
        }

        if (!paymentMatcher.matchesPaymentInitiation(methodArn)) {
            context.getLogger().log("Authorizer denied: methodArn is not payment initiation: " + methodArn);
            return denyPolicy("invalid-route", methodArn);
        }

        if (cleanToken == null || cleanToken.isBlank()) {
            context.getLogger().log("Authorizer denied: empty bearer token");
            return denyPolicy("anonymous", methodArn);
        }
        return null;
    }

    // Returns a policy document that will allow the guarded api to be invoked.
    private static Map<String, Object> allowPolicyDocument(String methodArn) {
        Map<String, Object> statement = new HashMap<>();
        statement.put("Action", "execute-api:Invoke");
        statement.put("Effect", "Allow");
        statement.put("Resource", methodArn);

        Map<String, Object> doc = new HashMap<>();
        doc.put("Version", "2012-10-17");
        doc.put("Statement", List.of(statement));
        return doc;
    }

    // Returns a policy that will deny all access.
    private static Map<String, Object> denyPolicy(String principalId, String methodArn) {
        String resource = methodArn != null ? methodArn : "*";
        Map<String, Object> statement = new HashMap<>();
        statement.put("Action", "execute-api:Invoke");
        statement.put("Effect", "Deny");
        statement.put("Resource", resource);

        Map<String, Object> doc = new HashMap<>();
        doc.put("Version", "2012-10-17");
        doc.put("Statement", List.of(statement));

        Map<String, Object> response = new HashMap<>();
        response.put("principalId", principalId);
        response.put("policyDocument", doc);
        return response;
    }

    private static String stringVal(Object o) {
        return o == null ? null : String.valueOf(o);
    }

    // Used to strip the "Bearer " prefix from the authorization token
    private static String stripBearer(String header) {
        String h = header.trim();
        if (h.regionMatches(true, 0, "Bearer ", 0, 7)) {
            return h.substring(7).trim();
        }
        return h;
    }
}
