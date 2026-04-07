package com.ryanwoolf.api;

import java.util.Map;

/**
 * Reads headers from API Gateway proxy / authorizer events (case-insensitive key match).
 */
public final class ApiGatewayHeaderExtractor {

    private ApiGatewayHeaderExtractor() {}

    public static String getHeader(Map<String, Object> event, String name) {
        Object headersObj = event.get("headers");
        if (!(headersObj instanceof Map<?, ?> headers)) {
            return null;
        }
        for (Map.Entry<?, ?> entry : headers.entrySet()) {
            String key = String.valueOf(entry.getKey());
            if (name.equalsIgnoreCase(key)) {
                Object v = entry.getValue();
                return v == null ? null : String.valueOf(v);
            }
        }
        return null;
    }
}
