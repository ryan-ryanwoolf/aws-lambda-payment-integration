package com.ryanwoolf.auth;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ryanwoolf.authorizer.util.Env;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueRequest;

import java.io.IOException;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Loads RSA PEM material from AWS Secrets Manager (JSON key/value or raw PEM) with in-memory caching.
 * Falls back to environment variables for local development.
 */
public final class JwtSecretPemLoader {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static final ConcurrentHashMap<String, String> CACHE = new ConcurrentHashMap<>();
    private static volatile SecretsManagerClient secretsClient;

    private JwtSecretPemLoader() {}

    /**
     * If {@code JWT_RSA_PRIVATE_KEY_SECRET_ID} is set, loads that secret (JSON field
     * {@code JWT_RSA_PRIVATE_KEY_SECRET_JSON_KEY}, default {@code JWT_RSA_PRIVATE_KEY_PEM});
     * otherwise requires {@code JWT_RSA_PRIVATE_KEY_PEM}.
     */
    public static String loadPrivateKeyPem() {
        String secretId = Env.optional("JWT_RSA_PRIVATE_KEY_SECRET_ID", "").trim();
        if (!secretId.isEmpty()) {
            String jsonKey = Env.optional("JWT_RSA_PRIVATE_KEY_SECRET_JSON_KEY", "JWT_RSA_PRIVATE_KEY_PEM");
            return cached(secretId, jsonKey, () -> fetchAndExtract(secretId, jsonKey));
        }
        return Env.required("JWT_RSA_PRIVATE_KEY_PEM");
    }

    /**
     * If {@code JWT_RSA_PUBLIC_KEY_SECRET_ID} is set, loads that secret (JSON field
     * {@code JWT_RSA_PUBLIC_KEY_SECRET_JSON_KEY}, default {@code JWT_RSA_PUBLIC_KEY_PEM});
     * otherwise requires {@code JWT_RSA_PUBLIC_KEY_PEM}.
     */
    public static String loadPublicKeyPem() {
        String secretId = Env.optional("JWT_RSA_PUBLIC_KEY_SECRET_ID", "").trim();
        if (!secretId.isEmpty()) {
            String jsonKey = Env.optional("JWT_RSA_PUBLIC_KEY_SECRET_JSON_KEY", "JWT_RSA_PUBLIC_KEY_PEM");
            return cached(secretId, jsonKey, () -> fetchAndExtract(secretId, jsonKey));
        }
        return Env.required("JWT_RSA_PUBLIC_KEY_PEM");
    }

    private static String cached(String secretId, String jsonKey, java.util.function.Supplier<String> loader) {
        return CACHE.computeIfAbsent(secretId + "\0" + jsonKey, k -> loader.get());
    }

    private static String fetchAndExtract(String secretId, String jsonKey) {
        String secretString = client()
                .getSecretValue(GetSecretValueRequest.builder().secretId(secretId).build())
                .secretString();
        if (secretString == null || secretString.isBlank()) {
            throw new IllegalStateException("Secret has no SecretString payload: " + secretId);
        }
        return extractPem(secretString, jsonKey);
    }

    /**
     * If the payload looks like JSON, reads {@code jsonKey}. Otherwise returns the full string (raw PEM).
     */
    static String extractPem(String secretString, String jsonKey) {
        String trimmed = secretString.trim();
        if (!trimmed.startsWith("{")) {
            return trimmed;
        }
        try {
            JsonNode root = MAPPER.readTree(trimmed);
            if (!root.has(jsonKey)) {
                throw new IllegalStateException("Secret JSON missing key: " + jsonKey);
            }
            return root.get(jsonKey).asText();
        } catch (IOException e) {
            throw new IllegalStateException("Failed to parse secret as JSON: " + e.getMessage(), e);
        }
    }

    private static SecretsManagerClient client() {
        if (secretsClient == null) {
            synchronized (JwtSecretPemLoader.class) {
                if (secretsClient == null) {
                    String region = firstNonBlank(System.getenv("AWS_REGION"), System.getenv("AWS_DEFAULT_REGION"), "eu-west-1");
                    secretsClient = SecretsManagerClient.builder().region(Region.of(region)).build();
                }
            }
        }
        return secretsClient;
    }

    private static String firstNonBlank(String... values) {
        for (String v : values) {
            if (v != null && !v.isBlank()) {
                return v.trim();
            }
        }
        return "eu-west-1";
    }
}
