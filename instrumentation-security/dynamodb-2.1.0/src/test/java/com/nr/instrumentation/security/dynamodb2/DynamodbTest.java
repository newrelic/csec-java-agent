package com.nr.instrumentation.security.dynamodb2;

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
import software.amazon.awssdk.services.dynamodb.model.BatchExecuteStatementRequest;
import software.amazon.awssdk.services.dynamodb.model.BatchGetItemRequest;
import software.amazon.awssdk.services.dynamodb.model.BatchStatementRequest;
import software.amazon.awssdk.services.dynamodb.model.BatchWriteItemRequest;
import software.amazon.awssdk.services.dynamodb.model.DeleteItemRequest;
import software.amazon.awssdk.services.dynamodb.model.DescribeTableRequest;
import software.amazon.awssdk.services.dynamodb.model.ExecuteStatementRequest;
import software.amazon.awssdk.services.dynamodb.model.GetItemRequest;
import software.amazon.awssdk.services.dynamodb.model.PutItemRequest;
import software.amazon.awssdk.services.dynamodb.model.PutRequest;
import software.amazon.awssdk.services.dynamodb.model.QueryRequest;
import software.amazon.awssdk.services.dynamodb.model.ScanRequest;
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
@InstrumentationTestConfig(includePrefixes = {"com.nr.agent.security.dynamodb_2", "software.amazon.awssdk.core.client.handler"})
public class DynamodbTest {
    private static final int PORT = DynamoUtil.getRandomPort();
    private static DynamoDBProxyServer server;
    private static DynamoDbClient client;
    private static DynamoDbAsyncClient asyncClient;

    @BeforeClass
    public static void setUp() throws Exception {
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
            String req = "{\"RequestItems\":{\"test\":[{\"PutRequest\":{\"Item\":{\"artist\":{\"S\":\"Charlie\"},\"Genre\":{\"S\":\"Jazz\"}}}}]}}";
            Assert.assertEquals("Invalid req.", req, request.getQuery());
            Assert.assertEquals("Invalid req-type.", "write", request.getQueryType());
        }
    }

    @Test
    public void testBatchExecuteStmt() {
        batchExecuteStmtTxn();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        DynamoDBOperation operation = (DynamoDBOperation) operations.get(0);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.DYNAMO_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "batchExecuteStatement", operation.getMethodName());
        Assert.assertEquals("Invalid operation Category.", DynamoDBOperation.Category.PARTIQL, operation.getCategory());
        Assert.assertTrue("No payload detected", operation.getPayload().size() > 0);

        for(DynamoDBRequest request: operation.getPayload()) {
            String req = "{\"Statements\":[{\"Statement\":\"SELECT * FROM test where Genre = ?\",\"Parameters\":[{\"S\":\"Jazz\"}],\"ConsistentRead\":true}]}";
            Assert.assertEquals("Invalid stmt.", req, request.getQuery());
            Assert.assertEquals("Invalid stmt-type.", "read_write", request.getQueryType());
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
            String req = "{\"RequestItems\":{\"test\":{\"Keys\":[{\"artist\":{\"S\":\"Charlie\"}}]}}}";
            Assert.assertEquals("Invalid stmt.", req, request.getQuery());
            Assert.assertEquals("Invalid stmt-type.", "read", request.getQueryType());
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
            String req = "{\"TableName\":\"test\",\"Key\":{\"artist\":{\"S\":\"Charlie\"}},\"ProjectionExpression\":\"artist, Genre\"}";
            Assert.assertEquals("Invalid stmt.", req, request.getQuery());
            Assert.assertEquals("Invalid stmt-type.", "read", request.getQueryType());
        }
    }
    @Test
    public void testExecuteStmt() {
        executeStmtTxn();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        DynamoDBOperation operation = (DynamoDBOperation) operations.get(0);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.DYNAMO_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "executeStatement", operation.getMethodName());
        Assert.assertEquals("Invalid operation Category.", DynamoDBOperation.Category.PARTIQL, operation.getCategory());
        Assert.assertTrue("No payload detected", operation.getPayload().size() > 0);

        for(DynamoDBRequest request: operation.getPayload()) {
            String req = "{\"Statement\":\"SELECT * FROM test where Genre = ?\",\"Parameters\":[{\"S\":\"Jazz\"}],\"ConsistentRead\":true}";
            Assert.assertEquals("Invalid stmt.", req, request.getQuery());
            Assert.assertEquals("Invalid stmt-type.", "read_write", request.getQueryType());
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
            String req = "{\"TableName\":\"test\",\"Key\":{\"artist\":{\"S\":\"Charlie\"}}}";
            Assert.assertEquals("Invalid stmt.", req, request.getQuery());
            Assert.assertEquals("Invalid stmt-type.", "delete", request.getQueryType());
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
            String req = "{\"TableName\":\"test\",\"ProjectionExpression\":\"artist\",\"KeyConditionExpression\":\"artist = :val\",\"ExpressionAttributeValues\":{\":val\":{\"S\":\"Charlie\"}}}";
            Assert.assertEquals("Invalid stmt.", req, request.getQuery());
            Assert.assertEquals("Invalid stmt-type.", "read", request.getQueryType());
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
            String req = "{\"TableName\":\"test\",\"ProjectionExpression\":\"artist, Genre\"}";
            Assert.assertEquals("Invalid stmt.", req, request.getQuery());
            Assert.assertEquals("Invalid stmt-type.", "read", request.getQueryType());
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
            String req = "{\"TableName\":\"test\",\"Item\":{\"artist\":{\"S\":\"Charlie\"},\"Genre\":{\"S\":\"Jazz\"}}}";
            Assert.assertEquals("Invalid stmt.", req, request.getQuery());
            Assert.assertEquals("Invalid stmt-type.", "write", request.getQueryType());
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
            String req = "{\"TableName\":\"test\",\"Key\":{\"artist\":{\"S\":\"Charlie\"}},\"AttributeUpdates\":{\"Genre\":{\"Value\":{\"S\":\"Classic\"}}}}";
            Assert.assertEquals("Invalid stmt.", req, request.getQuery());
            Assert.assertEquals("Invalid stmt-type.", "update", request.getQueryType());
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
            String req = "{\"RequestItems\":{\"test\":[{\"PutRequest\":{\"Item\":{\"artist\":{\"S\":\"Charlie\"},\"Genre\":{\"S\":\"Jazz\"}}}}]}}";
            Assert.assertEquals("Invalid req.", req, request.getQuery());
            Assert.assertEquals("Invalid req-type.", "write", request.getQueryType());
        }
    }

    @Test
    public void testBatchExecuteStmtAsync() {
        batchExecuteStmtTxnAsync();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        DynamoDBOperation operation = (DynamoDBOperation) operations.get(0);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.DYNAMO_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "batchExecuteStatement", operation.getMethodName());
        Assert.assertEquals("Invalid operation Category.", DynamoDBOperation.Category.PARTIQL, operation.getCategory());
        Assert.assertTrue("No payload detected", operation.getPayload().size() > 0);

        for(DynamoDBRequest request: operation.getPayload()) {
            String req = "{\"Statements\":[{\"Statement\":\"SELECT * FROM test where Genre = ?\",\"Parameters\":[{\"S\":\"Jazz\"}],\"ConsistentRead\":true}]}";
            Assert.assertEquals("Invalid stmt.", req, request.getQuery());
            Assert.assertEquals("Invalid stmt-type.", "read_write", request.getQueryType());
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
            String req = "{\"RequestItems\":{\"test\":{\"Keys\":[{\"artist\":{\"S\":\"Charlie\"}}]}}}";
            Assert.assertEquals("Invalid stmt.", req, request.getQuery());
            Assert.assertEquals("Invalid stmt-type.", "read", request.getQueryType());
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
            String req = "{\"TableName\":\"test\",\"Key\":{\"artist\":{\"S\":\"Charlie\"}},\"ProjectionExpression\":\"artist, Genre\"}";
            Assert.assertEquals("Invalid stmt.", req, request.getQuery());
            Assert.assertEquals("Invalid stmt-type.", "read", request.getQueryType());
        }
    }
    @Test
    public void testExecuteStmtAsync() {
        executeStmtTxnAsync();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        DynamoDBOperation operation = (DynamoDBOperation) operations.get(0);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.DYNAMO_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "executeStatement", operation.getMethodName());
        Assert.assertEquals("Invalid operation Category.", DynamoDBOperation.Category.PARTIQL, operation.getCategory());
        Assert.assertTrue("No payload detected", operation.getPayload().size() > 0);

        for(DynamoDBRequest request: operation.getPayload()) {
            String req = "{\"Statement\":\"SELECT * FROM test where Genre = ?\",\"Parameters\":[{\"S\":\"Jazz\"}],\"ConsistentRead\":true}";
            Assert.assertEquals("Invalid stmt.", req, request.getQuery());
            Assert.assertEquals("Invalid stmt-type.", "read_write", request.getQueryType());
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
            String req = "{\"TableName\":\"test\",\"Key\":{\"artist\":{\"S\":\"Charlie\"}}}";
            Assert.assertEquals("Invalid stmt.", req, request.getQuery());
            Assert.assertEquals("Invalid stmt-type.", "delete", request.getQueryType());
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
            String req = "{\"TableName\":\"test\",\"ProjectionExpression\":\"artist\",\"KeyConditionExpression\":\"artist = :val\",\"ExpressionAttributeValues\":{\":val\":{\"S\":\"Charlie\"}}}";
            Assert.assertEquals("Invalid stmt.", req, request.getQuery());
            Assert.assertEquals("Invalid stmt-type.", "read", request.getQueryType());
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
            String req = "{\"TableName\":\"test\",\"ProjectionExpression\":\"artist, Genre\"}";
            Assert.assertEquals("Invalid stmt.", req, request.getQuery());
            Assert.assertEquals("Invalid stmt-type.", "read", request.getQueryType());
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
            String req = "{\"TableName\":\"test\",\"Item\":{\"artist\":{\"S\":\"Charlie\"},\"Genre\":{\"S\":\"Jazz\"}}}";
            Assert.assertEquals("Invalid stmt.", req, request.getQuery());
            Assert.assertEquals("Invalid stmt-type.", "write", request.getQueryType());
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
            String req = "{\"TableName\":\"test\",\"Key\":{\"artist\":{\"S\":\"Charlie\"}},\"AttributeUpdates\":{\"Genre\":{\"Value\":{\"S\":\"Classic\"}}}}";
            Assert.assertEquals("Invalid stmt.", req, request.getQuery());
            Assert.assertEquals("Invalid stmt-type.", "update", request.getQueryType());
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
    private void batchExecuteStmtTxn() {
        String stmt = "SELECT * FROM test where Genre = ?";
        client.batchExecuteStatement(
            BatchExecuteStatementRequest.builder()
            .statements(
                BatchStatementRequest.builder()
                    .statement(stmt)
                    .parameters(Collections.singletonList(AttributeValue.builder().s("Jazz").build()))
                    .consistentRead(true)
                    .build()
            )
            .build());
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
    private void executeStmtTxn() {
        String stmt = "SELECT * FROM test where Genre = ?";
        client.executeStatement(
            ExecuteStatementRequest.builder()
                .statement(stmt)
                .parameters(Collections.singletonList(AttributeValue.builder().s("Jazz").build()))
                .consistentRead(true)
                .build());
    }
    private void deleteItemTxn() {
        batchWriteTxn();
        client.deleteItem(
            DeleteItemRequest.builder()
                .tableName(DynamoUtil.TABLE)
                .key(DynamoUtil.getKey())
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
    private void batchExecuteStmtTxnAsync() {
        String stmt = "SELECT * FROM test where Genre = ?";
        asyncClient.batchExecuteStatement(
                BatchExecuteStatementRequest.builder()
                        .statements(
                                BatchStatementRequest.builder()
                                        .statement(stmt)
                                        .parameters(Collections.singletonList(AttributeValue.builder().s("Jazz").build()))
                                        .consistentRead(true)
                                        .build()
                        )
                        .build());
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
    private void executeStmtTxnAsync() {
        String stmt = "SELECT * FROM test where Genre = ?";
        asyncClient.executeStatement(
                ExecuteStatementRequest.builder()
                        .statement(stmt)
                        .parameters(Collections.singletonList(AttributeValue.builder().s("Jazz").build()))
                        .consistentRead(true)
                        .build());
    }
    private void deleteItemTxnAsync() {
        batchWriteTxnAsync();
        asyncClient.deleteItem(
                DeleteItemRequest.builder()
                        .tableName(DynamoUtil.TABLE)
                        .key(DynamoUtil.getKey())
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
}
