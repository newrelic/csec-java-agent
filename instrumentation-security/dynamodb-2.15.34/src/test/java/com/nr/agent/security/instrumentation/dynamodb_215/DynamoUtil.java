/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package com.nr.agent.security.instrumentation.dynamodb_215;

import software.amazon.awssdk.services.dynamodb.model.AttributeDefinition;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.CreateTableRequest;
import software.amazon.awssdk.services.dynamodb.model.KeySchemaElement;
import software.amazon.awssdk.services.dynamodb.model.KeyType;
import software.amazon.awssdk.services.dynamodb.model.KeysAndAttributes;
import software.amazon.awssdk.services.dynamodb.model.ProvisionedThroughput;
import software.amazon.awssdk.services.dynamodb.model.ScalarAttributeType;

import java.io.IOException;
import java.net.ServerSocket;
import java.util.HashMap;
import java.util.Map;

public class DynamoUtil {
    public static final String ACCESS_KEY = "access";
    public static final String SECRET_KEY = "secret";
    public static final String TABLE = "test";
    public static CreateTableRequest createTableRequest(String tableName) {
        return CreateTableRequest.builder()
            .tableName(tableName)
            .attributeDefinitions(
                AttributeDefinition.builder().attributeName("artist").attributeType(ScalarAttributeType.S).build()
            )
            .keySchema(
                KeySchemaElement.builder().attributeName("artist").keyType(KeyType.HASH).build()
            )
            .provisionedThroughput(
                ProvisionedThroughput.builder()
                    .readCapacityUnits(3L)
                    .writeCapacityUnits(3L)
                    .build()
            )
            .build();
    }

    public static Map<String, AttributeValue> getKey() {
        Map<String, AttributeValue> key = new HashMap<>();
        key.put("artist", AttributeValue.builder().s("Charlie").build());
        return key;
    }

    public static Map<String, KeysAndAttributes> getKeyAtt() {
        Map<String, KeysAndAttributes> keysAndAtt = new HashMap<>();
        keysAndAtt.put(TABLE, KeysAndAttributes.builder().keys(getKey()).projectionExpression("artist").build());
        return keysAndAtt;
    }

    public static int getRandomPort() {
        try (ServerSocket socket = new ServerSocket(0)){
            return socket.getLocalPort();
        } catch (IOException e) {
            throw new RuntimeException("Unable to allocate ephemeral PORT");
        }
    }
}
