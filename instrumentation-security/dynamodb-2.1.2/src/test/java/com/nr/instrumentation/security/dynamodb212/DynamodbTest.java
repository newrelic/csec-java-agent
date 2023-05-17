package com.nr.instrumentation.security.dynamodb212;

import com.amazonaws.services.dynamodbv2.local.main.ServerRunner;
import com.amazonaws.services.dynamodbv2.local.server.DynamoDBProxyServer;
import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.security.schema.helper.DynamoDBRequest;
import com.newrelic.api.agent.security.schema.operation.DynamoDBOperation;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;
import software.amazon.awssdk.auth.credentials.SystemPropertyCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.dynamodb.DynamoDbAsyncClient;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.AttributeValueUpdate;
import software.amazon.awssdk.services.dynamodb.model.BatchGetItemRequest;
import software.amazon.awssdk.services.dynamodb.model.BatchWriteItemRequest;
import software.amazon.awssdk.services.dynamodb.model.Delete;
import software.amazon.awssdk.services.dynamodb.model.DeleteItemRequest;
import software.amazon.awssdk.services.dynamodb.model.DescribeTableRequest;
import software.amazon.awssdk.services.dynamodb.model.Get;
import software.amazon.awssdk.services.dynamodb.model.GetItemRequest;
import software.amazon.awssdk.services.dynamodb.model.Put;
import software.amazon.awssdk.services.dynamodb.model.PutItemRequest;
import software.amazon.awssdk.services.dynamodb.model.PutRequest;
import software.amazon.awssdk.services.dynamodb.model.QueryRequest;
import software.amazon.awssdk.services.dynamodb.model.ScanRequest;
import software.amazon.awssdk.services.dynamodb.model.TransactGetItem;
import software.amazon.awssdk.services.dynamodb.model.TransactGetItemsRequest;
import software.amazon.awssdk.services.dynamodb.model.TransactWriteItem;
import software.amazon.awssdk.services.dynamodb.model.TransactWriteItemsRequest;
import software.amazon.awssdk.services.dynamodb.model.UpdateItemRequest;
import software.amazon.awssdk.services.dynamodb.model.WriteRequest;
import software.amazon.awssdk.services.dynamodb.waiters.DynamoDbWaiter;

import java.net.URI;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = {"com.nr.agent.security.dynamodb_212", "software.amazon.awssdk.core"})
public class DynamodbTest {
    private static final int PORT = DynamoUtil.getRandomPort();
    private static DynamoDBProxyServer server;
    private static DynamoDbClient client;
    private static DynamoDbAsyncClient asyncClient;

    @BeforeClass
    public static void setUp() throws Exception {
        System.setProperty("sqlite4java.library.path", "src/test/resources/libs/");
        System.setProperty("aws.accessKeyId", DynamoUtil.ACCESS_KEY);
        System.setProperty("aws.secretAccessKey", DynamoUtil.SECRET_KEY);

        server = ServerRunner.createServerFromCommandLineArgs(new String[]{ "-inMemory", "-port", String.valueOf(PORT) });
        server.start();

        URI endpoint = new URI("http://localhost:" + PORT);
        client = DynamoDbClient.builder()
                .credentialsProvider(SystemPropertyCredentialsProvider.create())
                .endpointOverride(endpoint)
                .region(Region.US_WEST_1)
                .build();

        asyncClient = DynamoDbAsyncClient.builder()
                .credentialsProvider(SystemPropertyCredentialsProvider.create())
                .endpointOverride(endpoint)
                .region(Region.US_WEST_1)
                .build();

        createTable();
    }

    @AfterClass
    public static void afterClass() throws Exception {
        if (server != null) {
            server.stop();
        }
    }
    @Test
    public void testBatchWrite() {
        batchWriteTxn();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        DynamoDBOperation operation = (DynamoDBOperation) operations.get(0);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.DYNAMO_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "executeBatchWriteItem", operation.getMethodName());
        Assert.assertEquals("Invalid operation Category.", DynamoDBOperation.Category.DQL, operation.getCategory());
        Assert.assertTrue("No payload detected", operation.getPayload().size() > 0);

        for(DynamoDBRequest request: operation.getPayload()) {
            Map<String, AttributeValue> query = (Map<String, AttributeValue>) request.getQuery().getItem();

            Assert.assertEquals("Invalid table name", "test", request.getQuery().getTableName());
            Assert.assertNotNull("No such payload detected", query.get("artist"));
            Assert.assertEquals("Invalid payload value.", "Charlie",query.get("artist").s());
            Assert.assertNotNull("No such payload detected", query.get("Genre"));
            Assert.assertEquals("Invalid payload value.", "Jazz",query.get("Genre").s());

            Assert.assertEquals("Invalid query-type.", "write", request.getQueryType());
        }
    }

    @Test
    public void testBatchGetItem() {
        batchGetItemTxn();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        DynamoDBOperation operation = (DynamoDBOperation) operations.get(0);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.DYNAMO_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "executeBatchGetItem", operation.getMethodName());
        Assert.assertEquals("Invalid operation Category.", DynamoDBOperation.Category.DQL, operation.getCategory());
        Assert.assertTrue("No payload detected", operation.getPayload().size() > 0);

        for(DynamoDBRequest request: operation.getPayload()) {
            Map<String, AttributeValue> query = ((List<Map<String, AttributeValue>>) request.getQuery().getKey()).get(0);

            Assert.assertEquals("Invalid table name", "test", request.getQuery().getTableName());
            Assert.assertNotNull("No such payload detected", query.get("artist"));
            Assert.assertEquals("Invalid payload value.", "Charlie",query.get("artist").s());
            Assert.assertEquals("Invalid payload value.", "artist",request.getQuery().getProjectionExpression());

            Assert.assertEquals("Invalid query-type.", "read", request.getQueryType());
        }
    }
    @Test
    public void testGetItem() {
        getItemTxn();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        DynamoDBOperation operation = (DynamoDBOperation) operations.get(0);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.DYNAMO_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "executeGetItem", operation.getMethodName());
        Assert.assertEquals("Invalid operation Category.", DynamoDBOperation.Category.DQL, operation.getCategory());
        Assert.assertTrue("No payload detected", operation.getPayload().size() > 0);

        for(DynamoDBRequest request: operation.getPayload()) {
            Map<String, AttributeValue> query = (Map<String, AttributeValue>) request.getQuery().getKey();

            Assert.assertEquals("Invalid table name", "test", request.getQuery().getTableName());
            Assert.assertNotNull("No such payload detected", query.get("artist"));
            Assert.assertEquals("Invalid payload value.", "Charlie",query.get("artist").s());
            Assert.assertEquals("Invalid payload value.", "artist, Genre",request.getQuery().getProjectionExpression());

            Assert.assertEquals("Invalid query-type.", "read", request.getQueryType());
        }
    }

    @Test
    public void testTransactGetItems() {
        transactGetItems();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        DynamoDBOperation operation = (DynamoDBOperation) operations.get(0);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.DYNAMO_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "transactGetItems", operation.getMethodName());
        Assert.assertEquals("Invalid operation Category.", DynamoDBOperation.Category.DQL, operation.getCategory());
        Assert.assertTrue("No payload detected", operation.getPayload().size() > 0);

        int i = 0;
        for(DynamoDBRequest request: operation.getPayload()) {
            Map<String, AttributeValue> query = (Map<String, AttributeValue>) request.getQuery().getKey();

            Assert.assertEquals("Invalid table name", "test", request.getQuery().getTableName());
            Assert.assertNotNull("No such payload detected", query.get("artist"));
            Assert.assertNotNull("No such payload detected", query.get("year"));
            if (i==0) {
                Assert.assertEquals("Invalid payload value.", "Monu",query.get("artist").s());
                Assert.assertEquals("Invalid payload value.", "1998",query.get("year").n());
            }
            else if (i==1) {
                Assert.assertEquals("Invalid payload value.", "Red",query.get("artist").s());
                Assert.assertEquals("Invalid payload value.", "1999",query.get("year").n());
            }
            Assert.assertEquals("Invalid payload value.", "artist",request.getQuery().getProjectionExpression());
            Assert.assertEquals("Invalid query-type.", "read", request.getQueryType());
            i++;
        }
    }

    @Test
    public void testTransactWriteItems() {
        transactWriteItems();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        DynamoDBOperation operation = (DynamoDBOperation) operations.get(0);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.DYNAMO_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "transactWriteItems", operation.getMethodName());
        Assert.assertEquals("Invalid operation Category.", DynamoDBOperation.Category.DQL, operation.getCategory());
        Assert.assertTrue("No payload detected", operation.getPayload().size() > 0);

        int i = 0;
        for(DynamoDBRequest request: operation.getPayload()) {
            if (i==0) {
                Map<String, AttributeValue> query = (Map<String, AttributeValue>) request.getQuery().getKey();
                Assert.assertEquals("Invalid table name", "test", request.getQuery().getTableName());
                Assert.assertNotNull("No such payload detected", query.get("artist"));
                Assert.assertEquals("Invalid payload value.", "Monu",query.get("artist").s());
                Assert.assertEquals("Invalid query-type.", "delete", request.getQueryType());
            }
            else if (i==1) {
                Map<String, AttributeValue> query = (Map<String, AttributeValue>) request.getQuery().getItem();
                Assert.assertEquals("Invalid table name", "test", request.getQuery().getTableName());
                Assert.assertNotNull("No such payload detected", query.get("artist"));
                Assert.assertEquals("Invalid payload value.", "Red",query.get("artist").s());
                Assert.assertNotNull("No such payload detected", query.get("year"));
                Assert.assertEquals("Invalid payload value.", "1998",query.get("year").n());
                Assert.assertEquals("Invalid query-type.", "write", request.getQueryType());
            }
            i++;
        }
    }

    @Test
    public void testDeleteItem() {
        deleteItemTxn();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        DynamoDBOperation operation = null;
        for (AbstractOperation op: operations) {
            if(op.getMethodName().equals("executeDeleteItem")){
                operation = (DynamoDBOperation) op;
            }
        }
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.DYNAMO_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "executeDeleteItem", operation.getMethodName());
        Assert.assertEquals("Invalid operation Category.", DynamoDBOperation.Category.DQL, operation.getCategory());
        Assert.assertTrue("No payload detected", operation.getPayload().size() > 0);

        for(DynamoDBRequest request: operation.getPayload()) {
            Map<String, AttributeValue> query = (Map<String, AttributeValue>) request.getQuery().getKey();

            Assert.assertEquals("Invalid table name", "test", request.getQuery().getTableName());
            Assert.assertNotNull("No such payload detected", query.get("artist"));
            Assert.assertEquals("Invalid payload value.", "Charlie",query.get("artist").s());

            Assert.assertEquals("Invalid query-type.", "delete", request.getQueryType());
        }
    }
    @Test
    public void testQuery() {
        queryTxn();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        DynamoDBOperation operation = (DynamoDBOperation) operations.get(0);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.DYNAMO_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "executeQuery", operation.getMethodName());
        Assert.assertEquals("Invalid operation Category.", DynamoDBOperation.Category.DQL, operation.getCategory());
        Assert.assertTrue("No payload detected", operation.getPayload().size() > 0);

        for(DynamoDBRequest request: operation.getPayload()) {
            DynamoDBRequest.Query query = request.getQuery();

            Assert.assertEquals("Invalid table name", "test", query.getTableName());
            Assert.assertEquals("Invalid key condition expression", "artist = :val", query.getKeyConditionExpression());
            Assert.assertEquals("Invalid projection expression.", "artist", query.getProjectionExpression());
            Assert.assertEquals("Invalid projection expression.", "Charlie", ((Map<String, AttributeValue>)query.getExpressionAttributeValues()).get(":val").s());


            Assert.assertEquals("Invalid query-type.", "read", request.getQueryType());
        }
    }
    @Test
    public void testScan() {
        scanTxn();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        DynamoDBOperation operation = (DynamoDBOperation) operations.get(0);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.DYNAMO_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "executeScan", operation.getMethodName());
        Assert.assertEquals("Invalid operation Category.", DynamoDBOperation.Category.DQL, operation.getCategory());
        Assert.assertTrue("No payload detected", operation.getPayload().size() > 0);

        for(DynamoDBRequest request: operation.getPayload()) {
            DynamoDBRequest.Query query = request.getQuery();

            Assert.assertEquals("Invalid table name", "test", query.getTableName());
            Assert.assertEquals("Invalid projection expression.", "artist, Genre", query.getProjectionExpression());

            Assert.assertEquals("Invalid query-type.", "read", request.getQueryType());
        }
    }
    @Test
    public void testPutItem() {
        putItemTxn();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        DynamoDBOperation operation = (DynamoDBOperation) operations.get(0);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.DYNAMO_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "executePutItem", operation.getMethodName());
        Assert.assertEquals("Invalid operation Category.", DynamoDBOperation.Category.DQL, operation.getCategory());
        Assert.assertTrue("No payload detected", operation.getPayload().size() > 0);

        for(DynamoDBRequest request: operation.getPayload()) {
            Map<String, AttributeValue> query = (Map<String, AttributeValue>) request.getQuery().getItem();

            Assert.assertEquals("Invalid table name", "test", request.getQuery().getTableName());
            Assert.assertNotNull("No such payload detected", query.get("artist"));
            Assert.assertEquals("Invalid payload value.", "Charlie",query.get("artist").s());
            Assert.assertNotNull("No such payload detected", query.get("Genre"));
            Assert.assertEquals("Invalid payload value.", "Jazz",query.get("Genre").s());

            Assert.assertEquals("Invalid query-type.", "write", request.getQueryType());
        }
    }
    @Test
    public void testUpdateItem() {
        updateItemTxn();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        DynamoDBOperation operation = (DynamoDBOperation) operations.get(0);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.DYNAMO_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "executeUpdateItem", operation.getMethodName());
        Assert.assertEquals("Invalid operation Category.", DynamoDBOperation.Category.DQL, operation.getCategory());
        Assert.assertTrue("No payload detected", operation.getPayload().size() > 0);

        for(DynamoDBRequest request: operation.getPayload()) {
            Map<String, AttributeValue> query = (Map<String, AttributeValue>) request.getQuery().getKey();
            Map<String, AttributeValueUpdate> attrs = (Map<String, AttributeValueUpdate>) request.getQuery().getAttributeUpdates();

            Assert.assertEquals("Invalid table name", "test", request.getQuery().getTableName());
            Assert.assertNotNull("No such payload detected", query.get("artist"));
            Assert.assertEquals("Invalid payload value.", "Charlie",query.get("artist").s());
            Assert.assertNotNull("No such payload detected", attrs.get("Genre"));
            Assert.assertEquals("Invalid payload value.", "Classic",attrs.get("Genre").value().s());

            Assert.assertEquals("Invalid query-type.", "update", request.getQueryType());
        }
    }
    @Test
    public void testBatchWriteAsync() {
        batchWriteTxnAsync();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        DynamoDBOperation operation = (DynamoDBOperation) operations.get(0);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.DYNAMO_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "executeBatchWriteItem", operation.getMethodName());
        Assert.assertEquals("Invalid operation Category.", DynamoDBOperation.Category.DQL, operation.getCategory());
        Assert.assertTrue("No payload detected", operation.getPayload().size() > 0);

        for(DynamoDBRequest request: operation.getPayload()) {
            Map<String, AttributeValue> query = (Map<String, AttributeValue>) request.getQuery().getItem();

            Assert.assertEquals("Invalid table name", "test", request.getQuery().getTableName());
            Assert.assertNotNull("No such payload detected", query.get("artist"));
            Assert.assertEquals("Invalid payload value.", "Charlie",query.get("artist").s());
            Assert.assertNotNull("No such payload detected", query.get("Genre"));
            Assert.assertEquals("Invalid payload value.", "Jazz",query.get("Genre").s());

            Assert.assertEquals("Invalid query-type.", "write", request.getQueryType());
        }
    }

    @Test
    public void testBatchGetItemAsync() {
        batchGetItemTxnAsync();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        DynamoDBOperation operation = (DynamoDBOperation) operations.get(0);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.DYNAMO_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "executeBatchGetItem", operation.getMethodName());
        Assert.assertEquals("Invalid operation Category.", DynamoDBOperation.Category.DQL, operation.getCategory());
        Assert.assertTrue("No payload detected", operation.getPayload().size() > 0);

        for(DynamoDBRequest request: operation.getPayload()) {
            Map<String, AttributeValue> query = ((List<Map<String, AttributeValue>>) request.getQuery().getKey()).get(0);

            Assert.assertEquals("Invalid table name", "test", request.getQuery().getTableName());
            Assert.assertNotNull("No such payload detected", query.get("artist"));
            Assert.assertEquals("Invalid payload value.", "Charlie",query.get("artist").s());
            Assert.assertEquals("Invalid payload value.", "artist",request.getQuery().getProjectionExpression());

            Assert.assertEquals("Invalid query-type.", "read", request.getQueryType());
        }
    }
    @Test
    public void testGetItemAsync() {
        getItemTxnAsync();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        DynamoDBOperation operation = (DynamoDBOperation) operations.get(0);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.DYNAMO_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "executeGetItem", operation.getMethodName());
        Assert.assertEquals("Invalid operation Category.", DynamoDBOperation.Category.DQL, operation.getCategory());
        Assert.assertTrue("No payload detected", operation.getPayload().size() > 0);

        for(DynamoDBRequest request: operation.getPayload()) {
            Map<String, AttributeValue> query = (Map<String, AttributeValue>) request.getQuery().getKey();

            Assert.assertEquals("Invalid table name", "test", request.getQuery().getTableName());
            Assert.assertNotNull("No such payload detected", query.get("artist"));
            Assert.assertEquals("Invalid payload value.", "Charlie",query.get("artist").s());
            Assert.assertEquals("Invalid payload value.", "artist, Genre",request.getQuery().getProjectionExpression());

            Assert.assertEquals("Invalid query-type.", "read", request.getQueryType());
        }
    }

    @Test
    public void testDeleteItemAsync() {
        deleteItemTxnAsync();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        DynamoDBOperation operation = null;
        for (AbstractOperation op: operations) {
            if(op.getMethodName().equals("executeDeleteItem")){
                operation = (DynamoDBOperation) op;
            }
        }
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.DYNAMO_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "executeDeleteItem", operation.getMethodName());
        Assert.assertEquals("Invalid operation Category.", DynamoDBOperation.Category.DQL, operation.getCategory());
        Assert.assertTrue("No payload detected", operation.getPayload().size() > 0);

        for(DynamoDBRequest request: operation.getPayload()) {
            Map<String, AttributeValue> query = (Map<String, AttributeValue>) request.getQuery().getKey();

            Assert.assertEquals("Invalid table name", "test", request.getQuery().getTableName());
            Assert.assertNotNull("No such payload detected", query.get("artist"));
            Assert.assertEquals("Invalid payload value.", "Charlie",query.get("artist").s());

            Assert.assertEquals("Invalid query-type.", "delete", request.getQueryType());
        }
    }
    @Test
    public void testQueryAsync() {
        queryTxnAsync();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        DynamoDBOperation operation = (DynamoDBOperation) operations.get(0);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.DYNAMO_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "executeQuery", operation.getMethodName());
        Assert.assertEquals("Invalid operation Category.", DynamoDBOperation.Category.DQL, operation.getCategory());
        Assert.assertTrue("No payload detected", operation.getPayload().size() > 0);

        for(DynamoDBRequest request: operation.getPayload()) {
            DynamoDBRequest.Query query = request.getQuery();

            Assert.assertEquals("Invalid table name", "test", query.getTableName());
            Assert.assertEquals("Invalid key condition expression", "artist = :val", query.getKeyConditionExpression());
            Assert.assertEquals("Invalid projection expression.", "artist", query.getProjectionExpression());
            Assert.assertEquals("Invalid projection expression.", "Charlie", ((Map<String, AttributeValue>)query.getExpressionAttributeValues()).get(":val").s());


            Assert.assertEquals("Invalid query-type.", "read", request.getQueryType());
        }
    }
    @Test
    public void testScanAsync() {
        scanTxnAsync();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        DynamoDBOperation operation = (DynamoDBOperation) operations.get(0);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.DYNAMO_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "executeScan", operation.getMethodName());
        Assert.assertEquals("Invalid operation Category.", DynamoDBOperation.Category.DQL, operation.getCategory());
        Assert.assertTrue("No payload detected", operation.getPayload().size() > 0);

        for(DynamoDBRequest request: operation.getPayload()) {
            DynamoDBRequest.Query query = request.getQuery();

            Assert.assertEquals("Invalid table name", "test", query.getTableName());
            Assert.assertEquals("Invalid projection expression.", "artist, Genre", query.getProjectionExpression());

            Assert.assertEquals("Invalid query-type.", "read", request.getQueryType());
        }
    }
    @Test
    public void testPutItemAsync() {
        putItemTxnAsync();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        DynamoDBOperation operation = (DynamoDBOperation) operations.get(0);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.DYNAMO_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "executePutItem", operation.getMethodName());
        Assert.assertEquals("Invalid operation Category.", DynamoDBOperation.Category.DQL, operation.getCategory());
        Assert.assertTrue("No payload detected", operation.getPayload().size() > 0);

        for(DynamoDBRequest request: operation.getPayload()) {
            Map<String, AttributeValue> query = (Map<String, AttributeValue>) request.getQuery().getItem();

            Assert.assertEquals("Invalid table name", "test", request.getQuery().getTableName());
            Assert.assertNotNull("No such payload detected", query.get("artist"));
            Assert.assertEquals("Invalid payload value.", "Charlie",query.get("artist").s());
            Assert.assertNotNull("No such payload detected", query.get("Genre"));
            Assert.assertEquals("Invalid payload value.", "Jazz",query.get("Genre").s());

            Assert.assertEquals("Invalid query-type.", "write", request.getQueryType());
        }
    }
    @Test
    public void testUpdateItemAsync() {
        updateItemTxnAsync();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        DynamoDBOperation operation = (DynamoDBOperation) operations.get(0);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.DYNAMO_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "executeUpdateItem", operation.getMethodName());
        Assert.assertEquals("Invalid operation Category.", DynamoDBOperation.Category.DQL, operation.getCategory());
        Assert.assertTrue("No payload detected", operation.getPayload().size() > 0);

        for(DynamoDBRequest request: operation.getPayload()) {
            Map<String, AttributeValue> query = (Map<String, AttributeValue>) request.getQuery().getKey();
            Map<String, AttributeValueUpdate> attrs = (Map<String, AttributeValueUpdate>) request.getQuery().getAttributeUpdates();

            Assert.assertEquals("Invalid table name", "test", request.getQuery().getTableName());
            Assert.assertNotNull("No such payload detected", query.get("artist"));
            Assert.assertEquals("Invalid payload value.", "Charlie",query.get("artist").s());
            Assert.assertNotNull("No such payload detected", attrs.get("Genre"));
            Assert.assertEquals("Invalid payload value.", "Classic",attrs.get("Genre").value().s());

            Assert.assertEquals("Invalid query-type.", "update", request.getQueryType());
        }
    }
    private void batchWriteTxn() {
        Map<String, AttributeValue> item = DynamoUtil.getKey();
        item.put("Genre", AttributeValue.builder().s("Jazz").build());

        Map<String, List<WriteRequest>> requestItems = new HashMap<>();
        requestItems.put(
            DynamoUtil.TABLE,
            Collections.singletonList(
                WriteRequest.builder().putRequest(
                        PutRequest.builder().item(item).build()
                ).build()
        ));
        client.batchWriteItem(
                BatchWriteItemRequest
                .builder()
                .requestItems(requestItems)
                .build()
        );
    }

    private void batchGetItemTxn() {
        client.batchGetItem(
                BatchGetItemRequest
                        .builder()
                        .requestItems(DynamoUtil.getKeyAtt())
                .build());
    }
    private void getItemTxn() {
        Map<String, AttributeValue> key = new HashMap<>();
        key.put("artist", AttributeValue.builder().s("Charlie").build());
        client.getItem(
            GetItemRequest.builder()
                    .tableName(DynamoUtil.TABLE)
                    .key(key)
                    .projectionExpression("artist, Genre")
                    .build()
            );
    }

    private void deleteItemTxn() {
        batchWriteTxn();
        client.deleteItem(
            DeleteItemRequest.builder()
                    .tableName(DynamoUtil.TABLE)
                    .key(DynamoUtil.getKey())
                    .conditionExpression("Genre = :val")
                    .expressionAttributeValues(Collections.singletonMap(":val", AttributeValue.builder().s("Jazz").build()))
                .build()
        );
    }
    private void queryTxn() {
        Map<String, AttributeValue> value = new HashMap<>();
        value.put(":val", AttributeValue.builder().s("Charlie").build());
        client.query(
            QueryRequest.builder()
                .tableName(DynamoUtil.TABLE)
                .keyConditionExpression("artist = :val")
                .expressionAttributeValues(value)
                .projectionExpression("artist")
                .build()
        );
    }
    private void scanTxn() {
        client.scan(
            ScanRequest.builder()
                .tableName(DynamoUtil.TABLE)
                .projectionExpression("artist, Genre")
                .build()
        );
    }
    private void putItemTxn() {
        Map<String, AttributeValue> item = DynamoUtil.getKey();
        item.put("Genre", AttributeValue.builder().s("Jazz").build());
        client.putItem(
            PutItemRequest.builder()
                .tableName(DynamoUtil.TABLE)
                .item(item)
                .build()
        );
    }
    private void updateItemTxn() {
        Map<String, AttributeValueUpdate> item = new HashMap<>();
        item.put("Genre", AttributeValueUpdate.builder().value(AttributeValue.builder().s("Classic").build()).build());
        client.updateItem(
            UpdateItemRequest.builder()
                .tableName(DynamoUtil.TABLE)
                .key(DynamoUtil.getKey())
                .attributeUpdates(item)
                .build()
        );
    }
    private void batchWriteTxnAsync() {
        Map<String, AttributeValue> item = DynamoUtil.getKey();
        item.put("Genre", AttributeValue.builder().s("Jazz").build());

        Map<String, List<WriteRequest>> requestItems = new HashMap<>();
        requestItems.put(
                DynamoUtil.TABLE,
                Collections.singletonList(
                        WriteRequest.builder().putRequest(
                                PutRequest.builder().item(item).build()
                        ).build()
                ));
        asyncClient.batchWriteItem(
                BatchWriteItemRequest
                        .builder()
                        .requestItems(requestItems)
                        .build()
        );
    }

    private void batchGetItemTxnAsync() {
        asyncClient.batchGetItem(
                BatchGetItemRequest
                        .builder()
                        .requestItems(DynamoUtil.getKeyAtt())
                        .build());
    }
    private void getItemTxnAsync() {
        Map<String, AttributeValue> key = new HashMap<>();
        key.put("artist", AttributeValue.builder().s("Charlie").build());
        asyncClient.getItem(
                GetItemRequest.builder()
                        .tableName(DynamoUtil.TABLE)
                        .key(key)
                        .projectionExpression("artist, Genre")
                        .build()
        );
    }

    private void deleteItemTxnAsync() {
        batchWriteTxnAsync();
        asyncClient.deleteItem(
                DeleteItemRequest.builder()
                        .tableName(DynamoUtil.TABLE)
                        .key(DynamoUtil.getKey())
                        .conditionExpression("Genre = :val")
                        .expressionAttributeValues(Collections.singletonMap(":val", AttributeValue.builder().s("Jazz").build()))
                        .build()
        );
    }
    private void queryTxnAsync() {
        Map<String, AttributeValue> value = new HashMap<>();
        value.put(":val", AttributeValue.builder().s("Charlie").build());
        asyncClient.query(
                QueryRequest.builder()
                        .tableName(DynamoUtil.TABLE)
                        .keyConditionExpression("artist = :val")
                        .expressionAttributeValues(value)
                        .projectionExpression("artist")
                        .build()
        );
    }
    private void scanTxnAsync() {
        asyncClient.scan(
                ScanRequest.builder()
                        .tableName(DynamoUtil.TABLE)
                        .projectionExpression("artist, Genre")
                        .build()
        );
    }
    private void putItemTxnAsync() {
        Map<String, AttributeValue> item = DynamoUtil.getKey();
        item.put("Genre", AttributeValue.builder().s("Jazz").build());
        asyncClient.putItem(
                PutItemRequest.builder()
                        .tableName(DynamoUtil.TABLE)
                        .item(item)
                        .build()
        );
    }
    private void updateItemTxnAsync() {
        Map<String, AttributeValueUpdate> item = new HashMap<>();
        item.put("Genre", AttributeValueUpdate.builder().value(AttributeValue.builder().s("Classic").build()).build());
        asyncClient.updateItem(
                UpdateItemRequest.builder()
                        .tableName(DynamoUtil.TABLE)
                        .key(DynamoUtil.getKey())
                        .attributeUpdates(item)
                        .build()
        );
    }
    private static void createTable() {
        DynamoDbWaiter dbWaiter = client.waiter();
        client.createTable(DynamoUtil.createTableRequest(DynamoUtil.TABLE));
        DescribeTableRequest tableRequest = DescribeTableRequest.builder()
                .tableName(DynamoUtil.TABLE)
                .build();
        dbWaiter.waitUntilTableExists(tableRequest);
    }
    public void transactGetItems() {

        Map<String, AttributeValue> key = new HashMap<>();
        key.put("artist", AttributeValue.builder().s("Monu").build());
        key.put("year", AttributeValue.builder().n("1998").build());
        Map<String, AttributeValue> key2 = new HashMap<>();
        key2.put("artist", AttributeValue.builder().s("Red").build());
        key2.put("year", AttributeValue.builder().n("1999").build());

        TransactGetItemsRequest queryRequest = TransactGetItemsRequest.builder().transactItems(
                TransactGetItem.builder().get(Get.builder().tableName(DynamoUtil.TABLE).key(key).projectionExpression("artist").build()).build(),
                TransactGetItem.builder().get(Get.builder().tableName(DynamoUtil.TABLE).key(key2).projectionExpression("artist").build()).build()).build();

        client.transactGetItems(queryRequest);
    }

    public void transactWriteItems() {
        Map<String, AttributeValue> key = new HashMap<>();
        key.put("artist", AttributeValue.builder().s("Monu").build());
        Map<String, AttributeValue> key2 = new HashMap<>();
        key2.put("artist", AttributeValue.builder().s("Red").build());
        key2.put("year", AttributeValue.builder().n("1998").build());

        TransactWriteItemsRequest queryRequest = TransactWriteItemsRequest.builder().transactItems(
                TransactWriteItem.builder().delete(Delete.builder().tableName(DynamoUtil.TABLE).key(key).build()).build(),
                TransactWriteItem.builder().put(Put.builder().tableName(DynamoUtil.TABLE).item(key2).build()).build()).build();

        client.transactWriteItems(queryRequest);
    }
}
