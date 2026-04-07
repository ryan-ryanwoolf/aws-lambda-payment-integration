package com.ryanwoolf.auth;

import com.ryanwoolf.authorizer.TestLambdaContext;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class JwtPolicyAuthorizerHandlerTest {

    private static final String METHOD_ARN =
            "arn:aws:execute-api:eu-west-1:123456789012:abc123/production/POST/payments";

    private static JwtTokenService testJwt(KeyPair keyPair) {
        return JwtTestKeys.jwtService(keyPair, 600);
    }

    @Test
    void validToken_returnsAllowPolicyWithContext() {
        KeyPair kp = JwtTestKeys.rsa2048();
        JwtTokenService jwt = testJwt(kp);
        JwtPolicyAuthorizerHandler handler = new JwtPolicyAuthorizerHandler(jwt, new MethodArnPaymentMatcher());

        String token = jwt.createAccessToken("super-user", "Super User");
        Map<String, Object> event = Map.of(
                "type", "TOKEN",
                "methodArn", METHOD_ARN,
                "authorizationToken", "Bearer " + token);

        Map<String, Object> result = handler.handleRequest(event, new TestLambdaContext());

        assertEquals("partner|super-user", result.get("principalId"));
        @SuppressWarnings("unchecked")
        Map<String, Object> policy = (Map<String, Object>) result.get("policyDocument");
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> statements =
                (List<Map<String, Object>>) policy.get("Statement");
        assertEquals("Allow", statements.getFirst().get("Effect"));
        assertEquals(METHOD_ARN, statements.getFirst().get("Resource"));

        @SuppressWarnings("unchecked")
        Map<String, Object> ctx = (Map<String, Object>) result.get("context");
        assertNotNull(ctx);
        assertEquals("super-user", ctx.get("partnerId"));
    }

    @Test
    void wrongResource_returnsDeny() {
        KeyPair kp = JwtTestKeys.rsa2048();
        JwtTokenService jwt = testJwt(kp);
        JwtPolicyAuthorizerHandler handler = new JwtPolicyAuthorizerHandler(jwt, new MethodArnPaymentMatcher());

        String token = jwt.createAccessToken("super-user", "Super User");
        String wrongArn = METHOD_ARN.replace("payments", "auth/token");
        Map<String, Object> event = Map.of(
                "type", "TOKEN",
                "methodArn", wrongArn,
                "authorizationToken", "Bearer " + token);

        Map<String, Object> result = handler.handleRequest(event, new TestLambdaContext());

        @SuppressWarnings("unchecked")
        Map<String, Object> policy = (Map<String, Object>) result.get("policyDocument");
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> statements =
                (List<Map<String, Object>>) policy.get("Statement");
        assertEquals("Deny", statements.getFirst().get("Effect"));
    }

    @Test
    void badToken_returnsDeny() {
        KeyPair kp = JwtTestKeys.rsa2048();
        JwtTokenService jwt = testJwt(kp);
        JwtPolicyAuthorizerHandler handler = new JwtPolicyAuthorizerHandler(jwt, new MethodArnPaymentMatcher());

        Map<String, Object> event = Map.of(
                "type", "TOKEN",
                "methodArn", METHOD_ARN,
                "authorizationToken", "Bearer not-a-valid-jwt");

        Map<String, Object> result = handler.handleRequest(event, new TestLambdaContext());

        @SuppressWarnings("unchecked")
        Map<String, Object> policy = (Map<String, Object>) result.get("policyDocument");
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> statements =
                (List<Map<String, Object>>) policy.get("Statement");
        assertEquals("Deny", statements.getFirst().get("Effect"));
    }
}
