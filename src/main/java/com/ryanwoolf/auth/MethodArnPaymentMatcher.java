package com.ryanwoolf.auth;

import com.ryanwoolf.authorizer.util.Env;

/**
 * Ensures API Gateway {@code methodArn} is the payment initiation route only
 * (fail closed).
 * <p>
 * ARN form:
 * {@code arn:aws:execute-api:region:account:apiId/stage/HTTP-VERB/resource-path}
 */
public final class MethodArnPaymentMatcher {

    private final String expectedVerb;
    private final String expectedResourcePath;

    public MethodArnPaymentMatcher() {
        this(
                Env.optional("PAYMENT_INITIATION_HTTP_METHOD", "POST"),
                Env.optional("PAYMENT_INITIATION_RESOURCE_PATH", "payments"));
    }

    MethodArnPaymentMatcher(String expectedVerb, String expectedResourcePath) {
        this.expectedVerb = expectedVerb.toUpperCase();
        this.expectedResourcePath = normalizeResourcePath(expectedResourcePath);
    }

    // Used to normalize the resource path so that we can compare the expected
    // resource path to the actual resource path
    private static String normalizeResourcePath(String path) {
        String p = path.trim();
        while (p.startsWith("/")) {
            p = p.substring(1);
        }
        return p;
    }

    /**
     * @return true if this request targets the configured payment initiation method
     *         + resource.
     */
    // Used to check if the methodArn matches the configured payment initiation method + resource
    public boolean matchesPaymentInitiation(String methodArn) {
        if (methodArn == null || methodArn.isBlank()) {
            return false;
        }
        String[] arnSegments = methodArn.split(":");
        if (arnSegments.length < 6) {
            return false;
        }
        String apiStageMethodResource = arnSegments[5];
        int firstSlash = apiStageMethodResource.indexOf('/');
        if (firstSlash < 0) {
            return false;
        }
        String remainder = apiStageMethodResource.substring(firstSlash + 1);
        String[] parts = remainder.split("/", 3);
        if (parts.length < 3) {
            return false;
        }
        String stage = parts[0];
        String httpVerb = parts[1];
        String resourcePath = parts[2];
        if (stage.isBlank()) {
            return false;
        }
        if (!expectedVerb.equalsIgnoreCase(httpVerb)) {
            return false;
        }
        String normalizedResource = normalizeResourcePath(resourcePath);
        return expectedResourcePath.equalsIgnoreCase(normalizedResource);
    }
}
