package com.ryanwoolf.api;

import com.amazonaws.services.lambda.runtime.Context;

import java.util.List;
import java.util.Map;

/**
 * Small utility to map handler exceptions into API Gateway-style JSON responses.
 * This provides a lightweight, ControllerAdvice-like pattern for plain Lambda handlers.
 */
public final class LambdaExceptionMapper {

    private LambdaExceptionMapper() {
    }

    public static Map<String, Object> map(
            Exception exception,
            Context context,
            String logPrefix,
            List<ExceptionRule> rules,
            ExceptionRule fallbackRule
    ) {
        ExceptionRule matched = null;
        for (ExceptionRule rule : rules) {
            if (rule.type().isInstance(exception)) {
                matched = rule;
                break;
            }
        }
        ExceptionRule ruleToApply = matched != null ? matched : fallbackRule;
        log(context, logPrefix, exception);
        return ApiGatewayResponses.jsonResponse(
                ruleToApply.statusCode(),
                ruleToApply.toBody(exception));
    }

    private static void log(Context context, String logPrefix, Exception exception) {
        context.getLogger().log(
                logPrefix + exception.getClass().getName() + ": " + exception.getMessage());
    }

    public record ExceptionRule(
            Class<? extends Exception> type,
            int statusCode,
            String errorCode,
            boolean includeExceptionMessage,
            String fixedMessage
    ) {
        public Map<String, Object> toBody(Exception exception) {
            if (includeExceptionMessage) {
                return Map.of(
                        "error", errorCode,
                        "message", String.valueOf(exception.getMessage()));
            }
            if (fixedMessage != null && !fixedMessage.isBlank()) {
                return Map.of(
                        "error", errorCode,
                        "message", fixedMessage);
            }
            return Map.of("error", errorCode);
        }

        public static ExceptionRule withExceptionMessage(
                Class<? extends Exception> type,
                int statusCode,
                String errorCode
        ) {
            return new ExceptionRule(type, statusCode, errorCode, true, null);
        }

        public static ExceptionRule withFixedMessage(
                Class<? extends Exception> type,
                int statusCode,
                String errorCode,
                String fixedMessage
        ) {
            return new ExceptionRule(type, statusCode, errorCode, false, fixedMessage);
        }

        public static ExceptionRule withoutMessage(
                Class<? extends Exception> type,
                int statusCode,
                String errorCode
        ) {
            return new ExceptionRule(type, statusCode, errorCode, false, null);
        }
    }
}
