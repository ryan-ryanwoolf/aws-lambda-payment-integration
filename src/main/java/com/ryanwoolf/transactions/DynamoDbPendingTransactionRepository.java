package com.ryanwoolf.transactions;

import com.ryanwoolf.authorizer.util.Env;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.ConditionalCheckFailedException;
import software.amazon.awssdk.services.dynamodb.model.DynamoDbException;
import software.amazon.awssdk.services.dynamodb.model.PutItemRequest;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

/**
 * Writes pending transactions to DynamoDB. Partition key attribute stores the composite idempotency key.
 */
public final class DynamoDbPendingTransactionRepository implements PendingTransactionRepository {

    static final String ATTR_PARTNER_ID = "partnerId";
    static final String ATTR_STATUS = "status";
    static final String ATTR_CREATED_AT = "createdAt";
    static final String STATUS_PENDING = "PENDING";

    private final DynamoDbClient dynamoDbClient;
    private final String tableName;
    private final String partitionKeyAttribute;

    public DynamoDbPendingTransactionRepository() {
        this(
                DynamoDbClient.create(),
                Env.required("TRANSACTIONS_TABLE_NAME"),
                Env.optional("TRANSACTIONS_TABLE_PK_ATTRIBUTE", "idempotencyKey"));
    }

    DynamoDbPendingTransactionRepository(
            DynamoDbClient dynamoDbClient,
            String tableName,
            String partitionKeyAttribute) {
        this.dynamoDbClient = dynamoDbClient;
        this.tableName = tableName;
        this.partitionKeyAttribute = partitionKeyAttribute;
    }

    // Used to create a new pending transaction if it does not already exist
    @Override
    public void createIfAbsent(String compositeIdempotencyKey, String partnerId) throws DuplicateTransactionException {
        String createdAt = Instant.now().toString();
        Map<String, AttributeValue> item = new HashMap<>();
        item.put(partitionKeyAttribute, AttributeValue.builder().s(compositeIdempotencyKey).build());
        item.put(ATTR_PARTNER_ID, AttributeValue.builder().s(partnerId).build());
        item.put(ATTR_STATUS, AttributeValue.builder().s(STATUS_PENDING).build());
        item.put(ATTR_CREATED_AT, AttributeValue.builder().s(createdAt).build());

        PutItemRequest request = PutItemRequest.builder()
                .tableName(tableName)
                .item(item)
                .conditionExpression("attribute_not_exists(#pk)")
                .expressionAttributeNames(Map.of("#pk", partitionKeyAttribute))
                .build();

        try {
            dynamoDbClient.putItem(request);
        } catch (ConditionalCheckFailedException e) {
            throw new DuplicateTransactionException();
        } catch (DynamoDbException e) {
            throw new RuntimeException("Failed to write transaction: " + e.getMessage(), e);
        }
    }
}
