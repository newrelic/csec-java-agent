/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package com.newrelic.agent.security.instrumentation.dynamodb_1_11_80;

import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.client.builder.AwsClientBuilder;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDBAsync;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDBAsyncClientBuilder;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDBClientBuilder;
import com.amazonaws.services.dynamodbv2.document.AttributeUpdate;
import com.amazonaws.services.dynamodbv2.document.DynamoDB;
import com.amazonaws.services.dynamodbv2.document.Item;
import com.amazonaws.services.dynamodbv2.document.ItemCollection;
import com.amazonaws.services.dynamodbv2.document.KeyAttribute;
import com.amazonaws.services.dynamodbv2.document.PrimaryKey;
import com.amazonaws.services.dynamodbv2.document.QueryOutcome;
import com.amazonaws.services.dynamodbv2.document.ScanOutcome;
import com.amazonaws.services.dynamodbv2.document.TableKeysAndAttributes;
import com.amazonaws.services.dynamodbv2.document.TableWriteItems;
import com.amazonaws.services.dynamodbv2.document.spec.BatchGetItemSpec;
import com.amazonaws.services.dynamodbv2.document.spec.BatchWriteItemSpec;
import com.amazonaws.services.dynamodbv2.document.spec.DeleteItemSpec;
import com.amazonaws.services.dynamodbv2.document.spec.GetItemSpec;
import com.amazonaws.services.dynamodbv2.document.spec.PutItemSpec;
import com.amazonaws.services.dynamodbv2.document.spec.QuerySpec;
import com.amazonaws.services.dynamodbv2.document.spec.ScanSpec;
import com.amazonaws.services.dynamodbv2.document.spec.UpdateItemSpec;
import com.amazonaws.services.dynamodbv2.document.utils.ValueMap;
import com.amazonaws.services.dynamodbv2.local.main.ServerRunner;
import com.amazonaws.services.dynamodbv2.local.server.DynamoDBProxyServer;
import com.amazonaws.services.dynamodbv2.model.AttributeDefinition;
import com.amazonaws.services.dynamodbv2.model.AttributeValue;
import com.amazonaws.services.dynamodbv2.model.BatchGetItemRequest;
import com.amazonaws.services.dynamodbv2.model.BatchGetItemResult;
import com.amazonaws.services.dynamodbv2.model.BatchWriteItemRequest;
import com.amazonaws.services.dynamodbv2.model.BatchWriteItemResult;
import com.amazonaws.services.dynamodbv2.model.CreateTableRequest;
import com.amazonaws.services.dynamodbv2.model.DeleteItemRequest;
import com.amazonaws.services.dynamodbv2.model.DeleteItemResult;
import com.amazonaws.services.dynamodbv2.model.GetItemRequest;
import com.amazonaws.services.dynamodbv2.model.GetItemResult;
import com.amazonaws.services.dynamodbv2.model.KeySchemaElement;
import com.amazonaws.services.dynamodbv2.model.KeyType;
import com.amazonaws.services.dynamodbv2.model.KeysAndAttributes;
import com.amazonaws.services.dynamodbv2.model.ProvisionedThroughput;
import com.amazonaws.services.dynamodbv2.model.PutItemRequest;
import com.amazonaws.services.dynamodbv2.model.PutItemResult;
import com.amazonaws.services.dynamodbv2.model.PutRequest;
import com.amazonaws.services.dynamodbv2.model.QueryRequest;
import com.amazonaws.services.dynamodbv2.model.QueryResult;
import com.amazonaws.services.dynamodbv2.model.ScalarAttributeType;
import com.amazonaws.services.dynamodbv2.model.ScanRequest;
import com.amazonaws.services.dynamodbv2.model.ScanResult;
import com.amazonaws.services.dynamodbv2.model.UpdateItemRequest;
import com.amazonaws.services.dynamodbv2.model.UpdateItemResult;
import com.amazonaws.services.dynamodbv2.model.WriteRequest;
import com.amazonaws.services.dynamodbv2.util.TableUtils;
import com.amazonaws.services.dynamodbv2.xspec.ExpressionSpecBuilder;
import com.newrelic.api.agent.Trace;
import org.junit.rules.ExternalResource;

import java.io.IOException;
import java.net.ServerSocket;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;

public class DynamoServer extends ExternalResource {
    public final String TABLE = "test";
    public final String SECOND_TABLE = "second_table";
    public final String CONDITION = "Genre = :val";
    public final String UPDATE_CONDITION = "set Genre = :newVal";
    private DynamoDBProxyServer server;
    private AmazonDynamoDB DynamoDB;
    private AmazonDynamoDBAsync DynamoDBAsync;
    private final int PORT = getRandomPort();
    private static DynamoDB dynamo;

    private void setUp() throws Exception {
        System.setProperty("sqlite4java.library.path", "src/test/resources/libs/");

        server = ServerRunner.createServerFromCommandLineArgs(new String[]{ "-inMemory", "-port", String.valueOf(PORT) });
        server.start();

        AWSStaticCredentialsProvider credProv = new AWSStaticCredentialsProvider(
                new BasicAWSCredentials("access", "secret")
        );
        AwsClientBuilder.EndpointConfiguration endpointConfig = new AwsClientBuilder.EndpointConfiguration("http://localhost:" + PORT, "us-west-1");

        DynamoDB = AmazonDynamoDBClientBuilder.standard()
                .withCredentials(credProv)
                .withEndpointConfiguration(endpointConfig)
                .build();
        DynamoDBAsync = AmazonDynamoDBAsyncClientBuilder.standard()
                .withCredentials(credProv)
                .withEndpointConfiguration(endpointConfig)
                .build();
        dynamo = new DynamoDB(DynamoDB);

        System.out.println(System.getProperty("AWS_PROFILE"));
        createTableIfNotExists(TABLE);
        createTableIfNotExists(SECOND_TABLE);
    }

    private void stop() throws Exception {
        if (server != null) {
            DynamoDBAsync.shutdown();
            dynamo.shutdown();
            DynamoDB.shutdown();
            server.stop();
        }
    }
    @Override
    protected void before() throws Exception{
        setUp();
    }
    @Override
    protected void after() {
        try {
            stop();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Trace(dispatcher = true)
    public void batchGetTxn0() {
        TableKeysAndAttributes attributes1 = new TableKeysAndAttributes(TABLE);
        attributes1.addHashAndRangePrimaryKey("artist", "Charlie", "year", 2000);

        TableKeysAndAttributes attributes2 = new TableKeysAndAttributes(SECOND_TABLE);
        attributes2.addHashAndRangePrimaryKey("artist", "Charlie", "year", 2000);

        dynamo.batchGetItem(attributes1, attributes2);
    }
    @Trace(dispatcher = true)
    public void batchGetTxn() {
        TableKeysAndAttributes attributes1 = new TableKeysAndAttributes(TABLE);
        attributes1.addHashAndRangePrimaryKey("artist", "Charlie", "year", 2000);
        attributes1.withProjectionExpression("artist, Genre");

        TableKeysAndAttributes attributes2 = new TableKeysAndAttributes(SECOND_TABLE);
        attributes2.addHashAndRangePrimaryKey("artist", "Charlie", "year", 2000);
        attributes2.withProjectionExpression("artist, Genre");

        dynamo.batchGetItem(attributes1, attributes2);
    }
    @Trace(dispatcher = true)
    public void batchGetTxn1() {
        TableKeysAndAttributes attributes1 = new TableKeysAndAttributes(TABLE);
        attributes1.addHashAndRangePrimaryKey("artist", "Charlie", "year", 2000);
        attributes1.withProjectionExpression("artist, Genre");

        TableKeysAndAttributes attributes2 = new TableKeysAndAttributes(SECOND_TABLE);
        attributes2.addHashAndRangePrimaryKey("artist", "Charlie", "year", 2000);
        attributes2.withProjectionExpression("artist, Genre");

        BatchGetItemSpec batchGetItemSpec = new BatchGetItemSpec().withTableKeyAndAttributes(attributes1, attributes2);
        dynamo.batchGetItem(batchGetItemSpec);
    }

    @Trace(dispatcher = true)
    public void batchWriteTxn() {
        TableWriteItems table1WriteItems = new TableWriteItems(TABLE)
                .withItemsToPut(createItem());

        TableWriteItems table2WriteItems = new TableWriteItems(SECOND_TABLE)
                .withItemsToPut(createItem());

        dynamo.batchWriteItem(table1WriteItems, table2WriteItems);
    }
    @Trace(dispatcher = true)
    public void batchWriteTxn1() {
        TableWriteItems table1WriteItems = new TableWriteItems(TABLE)
                .withItemsToPut(createItem());

        TableWriteItems table2WriteItems = new TableWriteItems(SECOND_TABLE).withItemsToPut(createItem());
        BatchWriteItemSpec batchWriteItemSpec = new BatchWriteItemSpec().withTableWriteItems(table1WriteItems, table2WriteItems);

        dynamo.batchWriteItem(batchWriteItemSpec);
    }
    @Trace(dispatcher = true)
    public void deleteItemTxn0() {
        batchWriteTxn();
        DeleteItemSpec deleteItemSpec = new DeleteItemSpec()
                .withPrimaryKey(new KeyAttribute("artist", "Charlie"), new KeyAttribute("year", 2000));

        dynamo.getTable(TABLE).deleteItem(deleteItemSpec);
    }
    @Trace(dispatcher = true)
    public void deleteItemTxn() {
        batchWriteTxn();
        DeleteItemSpec deleteItemSpec = new DeleteItemSpec()
                .withPrimaryKey(new KeyAttribute("artist", "Charlie"), new KeyAttribute("year", 2000))
                .withConditionExpression(CONDITION)
                .withValueMap(new ValueMap().withString(":val", "Jazz"));

        dynamo.getTable(TABLE).deleteItem(deleteItemSpec);
    }
    @Trace(dispatcher = true)
    public void deleteItemTxn1() {
        batchWriteTxn();
        dynamo.getTable(TABLE).deleteItem(
                new PrimaryKey(
                        new KeyAttribute("artist", "Charlie"),
                        new KeyAttribute("year", 2000)
                ),
                CONDITION,
                null,
                new ValueMap().withString(":val", "Jazz")
        );
    }
    @Trace(dispatcher = true)
    public void deleteItemTxn2() {
        batchWriteTxn();
        dynamo.getTable(TABLE).deleteItem(
                new PrimaryKey(
                        new KeyAttribute("artist", "Charlie"),
                        new KeyAttribute("year", 2000)
                ),
                new ExpressionSpecBuilder()
                        .withCondition(ExpressionSpecBuilder.attribute_exists("Genre"))
                        .buildForDeleteItem()
        );
    }
    @Trace(dispatcher = true)
    public void deleteItemTxn3() {
        batchWriteTxn();

        dynamo.getTable(TABLE).deleteItem(
                "artist", "Charlie", "year", 2000,
                CONDITION,
                null,
                new ValueMap().withString(":val", "Jazz")
        );
    }
    @Trace(dispatcher = true)
    public void deleteItemTxn4() {
        batchWriteTxn();
        dynamo.getTable(TABLE).deleteItem(
                "artist", "Charlie", "year", 2000,
                new ExpressionSpecBuilder()
                        .withCondition(ExpressionSpecBuilder.attribute_exists("Genre"))
                        .buildForDeleteItem()
        );
    }
    @Trace(dispatcher = true)
    public void queryItemTxn() {
        QuerySpec querySpec = new QuerySpec()
                .withKeyConditionExpression("artist = :val")
                .withValueMap(new ValueMap().withString(":val", "Charlie"))
                .withConsistentRead(true);

        ItemCollection<QueryOutcome> itemCollection = dynamo.getTable(TABLE).query(querySpec);

        for (Item query : itemCollection) {
            query.getString("artist");
        }
    }
    @Trace(dispatcher = true)
    public void queryItemTxn1() {
        QuerySpec querySpec = new QuerySpec()
                .withKeyConditionExpression("artist = :val")
                .withFilterExpression("Genre = :genre")
                .withValueMap(
                        new ValueMap()
                                .withString(":val", "Charlie")
                                .withString(":genre", "Jazz"))
                .withConsistentRead(true);

        ItemCollection<QueryOutcome> itemCollection = dynamo.getTable(TABLE).query(querySpec);

        for (Item query : itemCollection) {
            query.getString("artist");
        }
    }
    @Trace(dispatcher = true)
    public void queryItemTxn2() {
        QuerySpec querySpec = new QuerySpec()
                .withKeyConditionExpression("artist = :val")
                .withFilterExpression("Genre = :genre")
                .withValueMap(
                        new ValueMap()
                                .withString(":val", "Charlie")
                                .withString(":genre", "Jazz"))
                .withProjectionExpression("artist, Genre")
                .withConsistentRead(true);

        ItemCollection<QueryOutcome> itemCollection = dynamo.getTable(TABLE).query(querySpec);

        for (Item query : itemCollection) {
            query.getString("artist");
        }
    }
    @Trace(dispatcher = true)
    public void getItemTxn0() {
        GetItemSpec getItemSpec = new GetItemSpec()
                .withPrimaryKey(new KeyAttribute("artist", "Charlie"), new KeyAttribute("year", 2000))
                .withConsistentRead(true);
        dynamo.getTable(TABLE).getItem(getItemSpec);
    }
    @Trace(dispatcher = true)
    public void getItemTxn() {
        GetItemSpec getItemSpec = new GetItemSpec()
                .withPrimaryKey(new KeyAttribute("artist", "Charlie"), new KeyAttribute("year", 2000))
                .withProjectionExpression("artist, Genre")
                .withConsistentRead(true);

        dynamo.getTable(TABLE).getItem(getItemSpec);
    }
    @Trace(dispatcher = true)
    public void getItemTxn1() {
        dynamo.getTable(TABLE).getItem("artist", "Charlie",
                "year", 2000,
                new ExpressionSpecBuilder()
                        .withCondition(ExpressionSpecBuilder.attribute_exists("Genre"))
                        .addProjection("artist, Genre")
                        .buildForGetItem());
    }
    @Trace(dispatcher = true)
    public void getItemTxn2() {
        GetItemSpec getItemSpec = new GetItemSpec()
                .withPrimaryKey(new KeyAttribute("artist", "Charlie"), new KeyAttribute("year", 2000))
                .withProjectionExpression("artist, Genre")
                .withConsistentRead(true);

        dynamo.getTable(TABLE).getItemOutcome(getItemSpec);
    }
    @Trace(dispatcher = true)
    public void getItemTxn3() {
        dynamo.getTable(TABLE).getItemOutcome("artist", "Charlie",
                "year", 2000,
                new ExpressionSpecBuilder()
                        .addProjection("artist, Genre")
                        .withCondition(ExpressionSpecBuilder.attribute_exists("Genre"))
                        .buildForGetItem());
    }

    @Trace(dispatcher = true)
    public void putItemTxn() {
        PutItemSpec putItemSpec = new PutItemSpec().withItem(createItem());
        dynamo.getTable(TABLE).putItem(putItemSpec);
    }
    @Trace(dispatcher = true)
    public void putItemTxn1() {
        dynamo.getTable(TABLE).putItem(createItem());
    }
    @Trace(dispatcher = true)
    public void putItemTxn2() {
        batchWriteTxn();
        dynamo.getTable(TABLE).putItem(
                createItem(),
                CONDITION,
                null,
                new ValueMap().withString(":val", "Jazz"));
    }
    @Trace(dispatcher = true)
    public void scanItemsTxn0() {
        ScanSpec scanSpec = new ScanSpec();
        ItemCollection<ScanOutcome> itemCollection = dynamo.getTable(TABLE).scan(scanSpec);
        for (Item query: itemCollection) {
            query.get("artist");
        }
    }
    @Trace(dispatcher = true)
    public void scanItemsTxn() {
        ScanSpec scanSpec = new ScanSpec()
                .withExpressionSpec(new ExpressionSpecBuilder()
                        .addProjection("artist, Genre")
                        .withCondition(ExpressionSpecBuilder.attribute_exists("Genre"))
                        .buildForScan()
                );

        ItemCollection<ScanOutcome> itemCollection = dynamo.getTable(TABLE).scan(scanSpec);
        for (Item query: itemCollection) {
            query.get("artist");
        }
    }
    @Trace(dispatcher = true)
    public void scanItemsTxn1() {
        ItemCollection<ScanOutcome> itemCollection = dynamo.getTable(TABLE).scan(
                CONDITION,
                "artist, Genre",
                null,
                new ValueMap().withString(":val", "Jazz")
        );
        for (Item query: itemCollection) {
            query.get("artist");
        }
    }
    @Trace(dispatcher = true)
    public void updateItemsTxn() {
        batchWriteTxn();
        dynamo.getTable(TABLE).updateItem(
                new PrimaryKey(new KeyAttribute("artist", "Charlie"), new KeyAttribute("year", 2000)),
                new AttributeUpdate("Genre").put("Classic")
        );
    }
    @Trace(dispatcher = true)
    public void updateItemsTxn1() {
        batchWriteTxn();
        UpdateItemSpec updateItemSpec = new UpdateItemSpec()
                .withPrimaryKey(new KeyAttribute("artist", "Charlie"), new KeyAttribute("year", 2000))
                .withConditionExpression(CONDITION)
                .withValueMap(new ValueMap().withString(":val", "Jazz").withString(":newVal", "Classic"))
                .withUpdateExpression(UPDATE_CONDITION);

        dynamo.getTable(TABLE).updateItem(updateItemSpec);

    }
    @Trace(dispatcher = true)
    public void updateItemsTxn2() {
        batchWriteTxn();
        dynamo.getTable(TABLE).updateItem(
                "artist", "Charlie",
                "year", 2000,
                new AttributeUpdate("Genre").put("Classic")
        );
    }
    @Trace(dispatcher = true)
    public void updateItemsTxn3() {
        batchWriteTxn();
        dynamo.getTable(TABLE).updateItem(
                "artist", "Charlie",
                "year", 2000,
                UPDATE_CONDITION,
                null,
                new ValueMap().withString(":newVal", "Classic")
        );
    }
    @Trace(dispatcher = true)
    public void updateItemsTxn4() {
        batchWriteTxn();
        dynamo.getTable(TABLE).updateItem(
                "artist", "Charlie",
                "year", 2000,
                UPDATE_CONDITION,
                CONDITION,
                null,
                new ValueMap().withString(":val", "Jazz").withString(":newVal", "Classic")
        );
    }

    @Trace(dispatcher = true)
    public void batchGetAsyncTxn0() throws ExecutionException, InterruptedException {
        Map<String, AttributeValue> key = getKey();


        KeysAndAttributes keysAndAttributes = new KeysAndAttributes().withKeys(key);
        Map<String, KeysAndAttributes> requestItems = new HashMap<>();
        requestItems.put(TABLE, keysAndAttributes);
        Future<BatchGetItemResult> future = DynamoDBAsync.batchGetItemAsync(new BatchGetItemRequest(requestItems));
        future.get();
    }
    @Trace(dispatcher = true)
    public void batchGetAsyncTxn() throws ExecutionException, InterruptedException {
        Map<String, AttributeValue> key = getKey();


        KeysAndAttributes keysAndAttributes = new KeysAndAttributes().withKeys(key).withProjectionExpression("artist, Genre");
        Map<String, KeysAndAttributes> requestItems = new HashMap<>();
        requestItems.put(TABLE, keysAndAttributes);
        Future<BatchGetItemResult> future = DynamoDBAsync.batchGetItemAsync(new BatchGetItemRequest(requestItems));
        future.get();
    }
    @Trace(dispatcher = true)
    public void batchWriteTxnAsync() throws ExecutionException, InterruptedException {
        Map<String, AttributeValue> key = getKey();
        key.put("Genre", new AttributeValue().withS("Jazz"));

        List<WriteRequest> write = new ArrayList<>(Collections.singletonList(new WriteRequest(new PutRequest(key))));
        Map<String, List<WriteRequest>> requestItems = new HashMap<>();
        requestItems.put(TABLE, write);

        Future<BatchWriteItemResult> future = DynamoDBAsync.batchWriteItemAsync(new BatchWriteItemRequest(requestItems));
        future.get();
    }
    @Trace(dispatcher = true)
    public void deleteTxnAsync() throws ExecutionException, InterruptedException {
        batchWriteTxnAsync();
        Map<String, AttributeValue> key = getKey();

        Map<String, AttributeValue> values = new HashMap<>();
        values.put(":val", new AttributeValue("Jazz"));

        Future<DeleteItemResult> future = DynamoDBAsync.deleteItemAsync(new DeleteItemRequest(TABLE, key)
                .withConditionExpression("Genre = :val")
                .withExpressionAttributeValues(values)
        );
        future.get();
    }
    @Trace(dispatcher = true)
    public void queryTxnAsync() throws ExecutionException, InterruptedException {
        batchWriteTxnAsync();
        Map<String, AttributeValue> values = new HashMap<>();
        values.put(":val", new AttributeValue("Charlie"));

        Future<QueryResult> future = DynamoDBAsync.queryAsync(new QueryRequest(TABLE)
                .withKeyConditionExpression("artist = :val")
                .withExpressionAttributeValues(values)
        );
        future.get();
    }
    @Trace(dispatcher = true)
    public void getItemsTxnAsync() throws ExecutionException, InterruptedException {
        batchWriteTxnAsync();
        Map<String, AttributeValue> key = getKey();

        Future<GetItemResult> future = DynamoDBAsync.getItemAsync(new GetItemRequest(TABLE, key)
                .withProjectionExpression("artist, Genre")
                .withConsistentRead(true)
        );
        future.get();
    }
    @Trace(dispatcher = true)
    public void putItemsTxnAsync() throws ExecutionException, InterruptedException {
        Map<String, AttributeValue> key = getKey();

        Future<PutItemResult> future = DynamoDBAsync.putItemAsync(new PutItemRequest(TABLE, key)
                .withItem(createItemKey())
        );
        future.get();
    }
    @Trace(dispatcher = true)
    public void scanTxnAsync() throws ExecutionException, InterruptedException {
        Future<ScanResult> future = DynamoDBAsync.scanAsync(new ScanRequest(TABLE)
                .withProjectionExpression("artist, Genre")
        );
        future.get();
    }
    @Trace(dispatcher = true)
    public void updateItemTxnAsync() throws ExecutionException, InterruptedException {
        batchWriteTxnAsync();
        Map<String, AttributeValue> key = getKey();

        Map<String, AttributeValue> values = new HashMap<>();
        values.put(":val", new AttributeValue("Jazz"));
        values.put(":newVal", new AttributeValue("Classic"));

        Future<UpdateItemResult> future = DynamoDBAsync.updateItemAsync(new UpdateItemRequest()
                .withTableName(TABLE)
                .withKey(key)
                .withConditionExpression(CONDITION)
                .withExpressionAttributeValues(values)
                .withUpdateExpression(UPDATE_CONDITION)
        );
        future.get();
    }

    private Item createItem() {
        return new Item()
                .withPrimaryKey("artist", "Charlie", "year", 2000)
                .withString("Genre", "Jazz");
    }
    private Map<String, AttributeValue> createItemKey() {
        Map<String, AttributeValue> key = new HashMap<>();
        key.put("artist", new AttributeValue("Charlie"));
        key.put("year", new AttributeValue().withN("2000"));
        key.put("Genre", new AttributeValue().withS("Jazz"));
        return key;
    }

    private Map<String, AttributeValue> getKey() {
        Map<String, AttributeValue> key = new HashMap<>();
        key.put("artist", new AttributeValue("Charlie"));
        key.put("year", new AttributeValue().withN("2000"));
        return key;
    }
    private void createTableIfNotExists(String table) {
        TableUtils.createTableIfNotExists(DynamoDB,
                new CreateTableRequest()
                        .withTableName(table)
                        .withKeySchema(Arrays.asList(
                                new KeySchemaElement("artist", KeyType.HASH),
                                new KeySchemaElement("year", KeyType.RANGE)))
                        .withAttributeDefinitions(
                                new AttributeDefinition("artist", ScalarAttributeType.S),
                                new AttributeDefinition("year", ScalarAttributeType.N))
                        .withProvisionedThroughput(new ProvisionedThroughput(3L, 3L))
        );
    }
    private int getRandomPort() {
        try (ServerSocket socket = new ServerSocket(0)){
            return socket.getLocalPort();
        } catch (IOException e) {
            throw new RuntimeException("Unable to allocate ephemeral PORT");
        }
    }
}
