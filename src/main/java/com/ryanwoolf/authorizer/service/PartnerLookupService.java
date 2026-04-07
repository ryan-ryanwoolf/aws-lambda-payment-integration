package com.ryanwoolf.authorizer.service;

import com.ryanwoolf.authorizer.model.PartnerRecord;
import com.ryanwoolf.authorizer.util.Env;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.GetItemRequest;
import software.amazon.awssdk.services.dynamodb.model.GetItemResponse;

import java.util.Map;
import java.util.logging.Logger;

public class PartnerLookupService implements PartnerLookup {
    private static final Logger LOGGER = Logger.getLogger(PartnerLookupService.class.getName());

    static final String ATTR_API_KEY_HASH = "apiKeyHash";
    static final String ATTR_PARTNER = "partner";
    static final String ATTR_ENABLED = "enabled";

    private final DynamoDbClient dynamoDbClient;
    private final Argon2ApiKeyHashService argon2ApiKeyHashService;
    private final String tableName;
    private final String partitionKeyAttributeName;

    public PartnerLookupService() {
        this(
                DynamoDbClient.create(),
                new Argon2ApiKeyHashService(),
                Env.required("PARTNER_TABLE_NAME"),
                Env.optional("PARTNER_TABLE_PK_ATTRIBUTE", "partnerId"));
    }

    PartnerLookupService(
            DynamoDbClient dynamoDbClient,
            Argon2ApiKeyHashService argon2ApiKeyHashService,
            String tableName,
            String partitionKeyAttributeName) {
        this.dynamoDbClient = dynamoDbClient;
        this.argon2ApiKeyHashService = argon2ApiKeyHashService;
        this.tableName = tableName;
        this.partitionKeyAttributeName = partitionKeyAttributeName;
    }

    @Override
    public PartnerRecord findByPartnerIdAndApiKey(String partnerId, String apiKey) {
        LOGGER.info(() -> "Partner lookup started: partnerId=" + partnerId + ", tableName=" + tableName);
        GetItemRequest request = GetItemRequest.builder()
                .tableName(tableName)
                .key(Map.of(
                        partitionKeyAttributeName, AttributeValue.builder().s(partnerId).build()))
                .build();

        GetItemResponse response = dynamoDbClient.getItem(request);

        if (response.item() == null || response.item().isEmpty()) {
            LOGGER.info(() -> "Partner lookup result: no row found for partnerId=" + partnerId);
            return null;
        }

        Map<String, AttributeValue> item = response.item();
        LOGGER.info(() -> "Partner lookup result: row found for partnerId=" + partnerId);

        if (!item.containsKey(ATTR_API_KEY_HASH) || item.get(ATTR_API_KEY_HASH).s() == null) {
            LOGGER.warning(() -> "Partner row missing apiKeyHash for partnerId=" + partnerId);
            return null;
        }

        String storedHash = item.get(ATTR_API_KEY_HASH).s();
        boolean hashMatches = argon2ApiKeyHashService.matches(apiKey, storedHash);
        LOGGER.info(() -> "API key hash verification result for partnerId=" + partnerId + ": " + hashMatches);
        if (!hashMatches) {
            return null;
        }

        String partner = item.containsKey(ATTR_PARTNER) ? item.get(ATTR_PARTNER).s() : null;
        boolean enabled = item.containsKey(ATTR_ENABLED) && Boolean.TRUE.equals(item.get(ATTR_ENABLED).bool());
        LOGGER.info(() -> "Partner enabled flag for partnerId=" + partnerId + ": " + enabled);

        return new PartnerRecord(partner, enabled);
    }
}
