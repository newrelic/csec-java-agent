package com.nr.agent.security.instrumentation.mongo38.client.internal;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.mongodb.AggregationOptions;
import com.mongodb.BasicDBObject;
import com.mongodb.DB;
import com.mongodb.DBCollection;
import com.mongodb.DBCursor;
import com.mongodb.DBObject;
import com.mongodb.MongoClient;
import com.mongodb.ParallelScanOptions;
import com.mongodb.ReadPreference;
import com.mongodb.WriteConcern;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoDatabase;
import com.mongodb.client.model.DBCollectionFindOptions;
import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.security.schema.operation.NoSQLOperation;
import de.flapdoodle.embed.mongo.MongodExecutable;
import de.flapdoodle.embed.mongo.MongodProcess;
import de.flapdoodle.embed.mongo.MongodStarter;
import de.flapdoodle.embed.mongo.config.ImmutableMongodConfig;
import de.flapdoodle.embed.mongo.config.MongodConfig;
import de.flapdoodle.embed.mongo.config.Net;
import de.flapdoodle.embed.mongo.distribution.Version;
import de.flapdoodle.embed.process.runtime.Network;
import org.bson.Document;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = {"com.mongodb.client.internal","com.mongodb.operation","com.nr.agent.security.mongo"})
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class OperationExecutorDBTest {

    private static final MongodStarter mongodStarter = MongodStarter.getDefaultInstance();
    private static MongodExecutable mongodExecutable;
    private static MongodProcess mongodProcess;
    private static MongoClient mongoClient;

    @BeforeClass
    public static void startMongo() throws Exception {
        int port = Network.getFreeServerPort();
        MongodConfig mongodConfig = ImmutableMongodConfig.builder()
                .version(Version.V4_0_12)
                .net(new Net(port, Network.localhostIsIPv6()))
                .build();

        mongodExecutable = mongodStarter.prepare(mongodConfig);
        mongodProcess = mongodExecutable.start();
        mongoClient = new MongoClient("localhost", port);
        MongoDatabase database = mongoClient.getDatabase("test");
        database.createCollection("test");
        MongoCollection mcollection = database.getCollection("test");
        Document doc = new Document("name", "MongoDB").append("type", "database").append("count", 1).append("info",
                new Document("x", 203).append("y", 102));
        mcollection.insertOne(doc);
    }

    @AfterClass
    public static void stopMongo() {
        if (mongoClient != null) {
            mongoClient.close();
        }
        if (mongodProcess != null) {
            mongodProcess.stop();
        }
        if (mongodExecutable != null) {
            mongodExecutable.stop();
        }
    }


    @Test
    public void testRemove() throws JsonProcessingException {

        DB database = mongoClient.getDB("test");
        DBCollection mcollection = database.getCollection("test");

        mcollection.remove(new BasicDBObject("name", "MongoDB"));
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        NoSQLOperation operation = (NoSQLOperation) operations.get(0);

        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertEquals("No Command Detected", "delete", operation.getPayloadType());

        List<Object> queryData = new ArrayList<>();
        queryData.add("{ \"name\" : \"MongoDB\" }");

        List<Object> expected = new ArrayList<>();
        expected.add(queryData);
        Assert.assertEquals("No data Found", queryData.toString(), operation.getPayload().toString());
    }

    @Test
    public void testRemove1()  {

        DB database = mongoClient.getDB("test");
        DBCollection mcollection = database.getCollection("test");
        mcollection.remove(new BasicDBObject("name", "MongoDB"), WriteConcern.ACKNOWLEDGED);
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        NoSQLOperation operation = (NoSQLOperation) operations.get(0);

        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertEquals("No Command Detected", "delete", operation.getPayloadType());
        List<Object> queryData = new ArrayList<>();
        queryData.add("{ \"name\" : \"MongoDB\" }");

        List<Object> expected = new ArrayList<>();
        expected.add(queryData);
        Assert.assertEquals("No data Found", queryData.toString(), operation.getPayload().toString());
    }

    @Test
    public void testAggregate()  {

        DB database = mongoClient.getDB("test");
        DBCollection mcollection = database.getCollection("test");
        DBObject fields = new BasicDBObject("type", 1);
        fields.put("attack", 1);
        fields.put("defense", 1);
        DBObject project = new BasicDBObject("$project", fields);
        List<DBObject> pipeline = Arrays.asList(project);
        mcollection.aggregate(pipeline);
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        NoSQLOperation operation = (NoSQLOperation) operations.get(0);

        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertEquals("No Command Detected", "aggregate", operation.getPayloadType());
        List<Object> queryData = new ArrayList<>();
        queryData.add("{ \"$project\" : { \"type\" : 1, \"attack\" : 1, \"defense\" : 1 } }");

        List<Object> expected = new ArrayList<>();
        expected.add(queryData);
        Assert.assertEquals("No data Found", queryData.toString(), operation.getPayload().toString());
    }

    @Test
    public void testAggregate1()  {

        DB database = mongoClient.getDB("test");
        DBCollection mcollection = database.getCollection("test");
        DBObject fields = new BasicDBObject("type", 1);
        fields.put("attack", 1);
        fields.put("defense", 1);
        DBObject project = new BasicDBObject("$project", fields);
        List<DBObject> pipeline = Arrays.asList(project);
        mcollection.aggregate(pipeline, ReadPreference.primary());
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        NoSQLOperation operation = (NoSQLOperation) operations.get(0);

        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertEquals("No Command Detected", "aggregate", operation.getPayloadType());
        List<Object> queryData = new ArrayList<>();
        queryData.add("{ \"$project\" : { \"type\" : 1, \"attack\" : 1, \"defense\" : 1 } }");

        List<Object> expected = new ArrayList<>();
        expected.add(queryData);
        Assert.assertEquals("No data Found", queryData.toString(), operation.getPayload().toString());
    }

    @Test
    public void testAggregate2()  {

        DB database = mongoClient.getDB("test");
        DBCollection mcollection = database.getCollection("test");
        DBObject fields = new BasicDBObject("type", 1);
        fields.put("attack", 1);
        fields.put("defense", 1);
        DBObject project = new BasicDBObject("$project", fields);
        List<DBObject> pipeline = Arrays.asList(project);
        AggregationOptions aggregationOptions = AggregationOptions.builder().batchSize(100)
                .outputMode(AggregationOptions.OutputMode.CURSOR).allowDiskUse(true).build();
        mcollection.aggregate(pipeline, aggregationOptions);
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        NoSQLOperation operation = (NoSQLOperation) operations.get(0);


        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertEquals("No Command Detected", "aggregate", operation.getPayloadType());
        List<Object> queryData = new ArrayList<>();
        queryData.add("{ \"$project\" : { \"type\" : 1, \"attack\" : 1, \"defense\" : 1 } }");

        List<Object> expected = new ArrayList<>();
        expected.add(queryData);
        Assert.assertEquals("No data Found", queryData.toString(), operation.getPayload().toString());
    }

    @Test
    public void testAggregate3()  {

        DB database = mongoClient.getDB("test");
        DBCollection mcollection = database.getCollection("test");
        DBObject fields = new BasicDBObject("type", 1);
        fields.put("attack", 1);
        fields.put("defense", 1);
        DBObject project = new BasicDBObject("$project", fields);
        List<DBObject> pipeline = Arrays.asList(project);
        AggregationOptions aggregationOptions = AggregationOptions.builder().batchSize(100)
                .outputMode(AggregationOptions.OutputMode.CURSOR).allowDiskUse(true).build();
        mcollection.aggregate(pipeline, aggregationOptions, ReadPreference.primary());
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        NoSQLOperation operation = (NoSQLOperation) operations.get(0);


        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertEquals("No Command Detected", "aggregate", operation.getPayloadType());
        List<Object> queryData = new ArrayList<>();
        queryData.add("{ \"$project\" : { \"type\" : 1, \"attack\" : 1, \"defense\" : 1 } }");

        List<Object> expected = new ArrayList<>();
        expected.add(queryData);
        Assert.assertEquals("No data Found", queryData.toString(), operation.getPayload().toString());
    }
    @Test
    @Ignore("this test case may fail, because this is not instrumented(AggregateExplainOperation)")
    public void testExplainAggregate()  {

        DB database = mongoClient.getDB("test");
        DBCollection mcollection = database.getCollection("test");
        DBObject fields = new BasicDBObject("type", 1);
        fields.put("attack", 1);
        fields.put("defense", 1);
        DBObject project = new BasicDBObject("$project", fields);
        List<DBObject> pipeline = Collections.singletonList(project);
        AggregationOptions aggregationOptions = AggregationOptions.builder().batchSize(100)
                .outputMode(AggregationOptions.OutputMode.CURSOR).allowDiskUse(true).build();
        mcollection.explainAggregate(pipeline,aggregationOptions);
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        NoSQLOperation operation = (NoSQLOperation) operations.get(0);

        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertEquals("No Command Detected", "aggregate", operation.getPayloadType());
        List<Object> queryData = new ArrayList<>();
        queryData.add("{ \"$project\" : { \"type\" : 1, \"attack\" : 1, \"defense\" : 1 } }");
        List<Object> expected = new ArrayList<>();
        expected.add(queryData);
        Assert.assertEquals("No data Found", queryData.toString(), operation.getPayload().toString());
    }

    @Test
    public void testCount()  {

        DB database = mongoClient.getDB("test");
        DBCollection mcollection = database.getCollection("test");

        mcollection.count();
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        NoSQLOperation operation = (NoSQLOperation) operations.get(0);

        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertEquals("No Command Detected", "count", operation.getPayloadType());
        List<Object> expected = new ArrayList<>();
        expected.add("{ }");
        Assert.assertEquals("No data Found", expected.toString(), operation.getPayload().toString());
    }

    @Test
    public void testCount1()  {

        DB database = mongoClient.getDB("test");
        DBCollection mcollection = database.getCollection("test");

        mcollection.count(new BasicDBObject("name", "MongoDB"));
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        NoSQLOperation operation = (NoSQLOperation) operations.get(0);

        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertEquals("No Command Detected", "count", operation.getPayloadType());
        List<Object> expected = new ArrayList<>();
        expected.add("{ \"name\" : \"MongoDB\" }");


        Assert.assertEquals("No data Found", expected.toString(), operation.getPayload().toString());
    }

    @Test
    public void testCount2()  {

        DB database = mongoClient.getDB("test");
        DBCollection mcollection = database.getCollection("test");

        mcollection.count(new BasicDBObject("name", "MongoDB"), ReadPreference.primary());
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        NoSQLOperation operation = (NoSQLOperation) operations.get(0);

        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertEquals("No Command Detected", "count", operation.getPayloadType());
        List<Object> expected = new ArrayList<>();
        expected.add("{ \"name\" : \"MongoDB\" }");


        Assert.assertEquals("No data Found", expected.toString(), operation.getPayload().toString());
    }

    @Test
    public void testDistinct()  {

        DB database = mongoClient.getDB("test");
        DBCollection mcollection = database.getCollection("test");

        mcollection.distinct("name");
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        NoSQLOperation operation = (NoSQLOperation) operations.get(0);

        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertEquals("No Command Detected", "distinct", operation.getPayloadType());
        List<Object> expected = new ArrayList<>();
        expected.add("{ }");
        Assert.assertEquals("No data Found", expected.toString(), operation.getPayload().toString());
    }

    @Test
    public void testDistinct1()  {

        DB database = mongoClient.getDB("test");
        DBCollection mcollection = database.getCollection("test");

        mcollection.distinct("name", ReadPreference.primary());
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        NoSQLOperation operation = (NoSQLOperation) operations.get(0);

        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertEquals("No Command Detected", "distinct", operation.getPayloadType());
        List<Object> expected = new ArrayList<>();
        expected.add("{ }");
        Assert.assertEquals("No data Found", expected.toString(), operation.getPayload().toString());
    }

    @Test
    public void testDistinct2()  {

        DB database = mongoClient.getDB("test");
        DBCollection mcollection = database.getCollection("test");

        mcollection.distinct("name", new BasicDBObject("type", "Database"));
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        NoSQLOperation operation = (NoSQLOperation) operations.get(0);

        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertEquals("No Command Detected", "distinct", operation.getPayloadType());
        List<Object> expected = new ArrayList<>();
        expected.add("{ \"type\" : \"Database\" }");


        Assert.assertEquals("No data Found", expected.toString(), operation.getPayload().toString());
    }

    @Test
    public void testFindAndRemove()  {

        DB database = mongoClient.getDB("test");

        DBCollection mcollection = database.getCollection("test");

        mcollection.findAndRemove(new BasicDBObject("name", "MongoDB"));
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        NoSQLOperation operation = (NoSQLOperation) operations.get(0);

        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertEquals("No Command Detected", "findAndDelete", operation.getPayloadType());
        List<Object> queryData = new ArrayList<>();
        queryData.add("{ \"name\" : \"MongoDB\" }");

        List<Object> expected = new ArrayList<>();
        expected.add(queryData);
        Assert.assertEquals("No data Found", queryData.toString(), operation.getPayload().toString());
    }

    @Test
    public void testFindAndModify()  {

        DB database = mongoClient.getDB("test");

        DBCollection mcollection = database.getCollection("test");

        mcollection.findAndModify(new BasicDBObject("name", "MongoDB"), new BasicDBObject("type", "db"));
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        NoSQLOperation operation = (NoSQLOperation) operations.get(0);

        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertEquals("No Command Detected", "write", operation.getPayloadType());
        List<Object> queryData = new ArrayList<>();
        queryData.add("{ \"name\" : \"MongoDB\" }, { \"type\" : \"db\" }");

        List<Object> expected = new ArrayList<>();
        expected.add(queryData);
        Assert.assertEquals("No data Found", queryData.toString(), operation.getPayload().toString());
    }

    @Test
    public void testFind()  {

        DB database = mongoClient.getDB("test");
        DBCollection mcollection = database.getCollection("test");
        DBObject query = new BasicDBObject("name", "MongoDB");
        try (DBCursor dbCursor = mcollection.find(query)) {
            Iterator<DBObject> var = dbCursor.iterator();
            while (var.hasNext()) {
                var.next().get("name");
            }
        }
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        NoSQLOperation operation = (NoSQLOperation) operations.get(0);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertEquals("No Command Detected", "find", operation.getPayloadType());
        List<Object> expected = new ArrayList<>();
        expected.add("{ \"name\" : \"MongoDB\" }");
        Assert.assertEquals("No data Found", expected.toString(), operation.getPayload().toString());
    }

    @Test
    public void testFind1()  {

        DB database = mongoClient.getDB("test");
        DBCollection mcollection = database.getCollection("test");

        try (DBCursor dbCursor = mcollection.find()) {
            Iterator<DBObject> var = dbCursor.iterator();
            while (var.hasNext()) {
                var.next().get("name");
            }
        }
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        NoSQLOperation operation = (NoSQLOperation) operations.get(0);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertEquals("No Command Detected", "find", operation.getPayloadType());
        List<Object> expected = new ArrayList<>();
        expected.add("{ }");

        Assert.assertEquals("No data Found", expected.toString(), operation.getPayload().toString());
    }

    @Test
    public void testFind2()  {

        DB database = mongoClient.getDB("test");
        DBCollection mcollection = database.getCollection("test");
        DBObject query = new BasicDBObject("name", "MongoDB");

        try (DBCursor dbCursor = mcollection.find(query,new BasicDBObject("type", "db"))) {
            Iterator<DBObject> var = dbCursor.iterator();
            while (var.hasNext()) {
                var.next().get("name");
            }
        }
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        NoSQLOperation operation = (NoSQLOperation) operations.get(0);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertEquals("No Command Detected", "find", operation.getPayloadType());
        List<Object> expected= new ArrayList<>();
        expected.add("{ \"name\" : \"MongoDB\" }");
        Assert.assertEquals("No data Found", expected.toString(), operation.getPayload().toString());
    }

    @Test
    public void testFind3()  {

        DB database = mongoClient.getDB("test");
        DBCollection mcollection = database.getCollection("test");
        DBObject query = new BasicDBObject("name", "MongoDB");
        DBCollectionFindOptions dbcollectionfindoptions=new DBCollectionFindOptions();
        try (DBCursor dbCursor = mcollection.find(query,dbcollectionfindoptions)) {
            Iterator<DBObject> var = dbCursor.iterator();
            while (var.hasNext()) {
                var.next().get("name");
            }
        }
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        NoSQLOperation operation = (NoSQLOperation) operations.get(0);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertEquals("No Command Detected", "find", operation.getPayloadType());
        List<Object> expected= new ArrayList<>();
        expected.add("{ \"name\" : \"MongoDB\" }");
        Assert.assertEquals("No data Found", expected.toString(), operation.getPayload().toString());
    }

    @Test
    public void testFindOne()  {

        DB database = mongoClient.getDB("test");
        DBCollection mcollection = database.getCollection("test");
        mcollection.findOne();
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        NoSQLOperation operation = (NoSQLOperation) operations.get(0);

        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertEquals("No Command Detected", "find", operation.getPayloadType());
        List<Object> expected = new ArrayList<>();
        expected.add("{ }");
        Assert.assertEquals("No data Found", expected.toString(), operation.getPayload().toString());
    }

    @Test
    public void testFindOne1()  {

        DB database = mongoClient.getDB("test");
        DBCollection mcollection = database.getCollection("test");
        DBObject obj = new BasicDBObject("name", "MongoDB");
        mcollection.findOne(obj);
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        NoSQLOperation operation = (NoSQLOperation) operations.get(0);

        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertEquals("No Command Detected", "find", operation.getPayloadType());
        List<Object> expected = new ArrayList<>();
        expected.add("{ \"name\" : \"MongoDB\" }");


        Assert.assertEquals("No data Found", expected.toString(), operation.getPayload().toString());
    }

    @Test
    public void testFindOne2()  {

        DB database = mongoClient.getDB("test");
        DBCollection mcollection = database.getCollection("test");
        DBObject obj = new BasicDBObject("name", "MongoDB");
        mcollection.findOne(obj, new BasicDBObject("type", "db"));
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        NoSQLOperation operation = (NoSQLOperation) operations.get(0);

        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertEquals("No Command Detected", "find", operation.getPayloadType());
        List<Object> expected = new ArrayList<>();
        expected.add("{ \"name\" : \"MongoDB\" }");


        Assert.assertEquals("No data Found", expected.toString(), operation.getPayload().toString());
    }

    @Test
    @Ignore("this testcase may fail")
    public void testGroup()  {

        DB database = mongoClient.getDB("test");
        DBCollection mcollection = database.getCollection("test");

        DBObject keys = new BasicDBObject("type", true);
        DBObject initial = new BasicDBObject("cnt", 0);
        DBObject cond = new BasicDBObject("type", "database");
        String reduce = "function(obj,prev){prev.cnt+=1;}";

        mcollection.group(keys, cond, initial, reduce);


        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        NoSQLOperation operation = (NoSQLOperation) operations.get(0);

        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertEquals("No Command Detected", "Group", operation.getPayloadType());
        List<Object> queryData = new ArrayList<>();
        queryData.add("{ \"name\" : \"MongoDB\" }");

        List<Object> expected = new ArrayList<>();
        expected.add(queryData);
        Assert.assertEquals("No data Found", queryData.toString(), operation.getPayload().toString());
    }

    @Test
    @Ignore("this testcase may fail")
    public void testMapReduceToCollection()  {

        DB database = mongoClient.getDB("test");
        DBCollection mcollection = database.getCollection("test");

        mcollection.mapReduce("function() { emit(this.firstName, this.type); }",
                "function(key, values) {return Array.sum(values)}", "ouput", new BasicDBObject("name", "MongoDB"));

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        NoSQLOperation operation = (NoSQLOperation) operations.get(0);

        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertEquals("No Command Detected", "mapReduce", operation.getPayloadType());
        List<Object> queryData = new ArrayList<>();
        queryData.add("{ \"name\" : \"MongoDB\" }");

        List<Object> expected = new ArrayList<>();
        expected.add(queryData);
        Assert.assertEquals("No data Found", queryData.toString(), operation.getPayload().toString());
    }


    @Test
    public void testInsert()  {

        DB database = mongoClient.getDB("test");
        DBCollection mcollection = database.getCollection("test");
        DBObject dbo = new BasicDBObject("name", "db");

        mcollection.insert(dbo);
        String id = dbo.get("_id").toString();
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        NoSQLOperation operation = (NoSQLOperation) operations.get(0);

        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertEquals("No Command Detected", "insert", operation.getPayloadType());
        List<Object> queryData = new ArrayList<>();
        String string = String.format("{ \"name\" : \"db\", \"_id\" : { \"$oid\" : \"%s\" } }", id);
        queryData.add(string);

        List<Object> expected = new ArrayList<>();
        expected.add(queryData);
        Assert.assertEquals("No data Found", queryData.toString(), operation.getPayload().toString());
    }

    @Test
    public void testInsert1()  {

        DB database = mongoClient.getDB("test");
        DBCollection mcollection = database.getCollection("test");
        DBObject dbo = new BasicDBObject("name", "db");

        mcollection.insert(dbo, WriteConcern.ACKNOWLEDGED);
        String id = dbo.get("_id").toString();
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        NoSQLOperation operation = (NoSQLOperation) operations.get(0);

        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertEquals("No Command Detected", "insert", operation.getPayloadType());
        List<Object> queryData = new ArrayList<>();
        String string = String.format("{ \"name\" : \"db\", \"_id\" : { \"$oid\" : \"%s\" } }", id);
        queryData.add(string);

        List<Object> expected = new ArrayList<>();
        expected.add(queryData);
        Assert.assertEquals("No data Found", queryData.toString(), operation.getPayload().toString());
    }

    @Test
    public void testInsert2()  {

        DB database = mongoClient.getDB("test");
        DBCollection mcollection = database.getCollection("test");
        DBObject doc1 = new BasicDBObject("name", "Mongo").append("type", "db").append("count", 1).append("info",
                new Document("x", 203).append("y", 102));
        List<DBObject> doc = new ArrayList<>();
        doc.add(doc1);
        mcollection.insert(doc);
        String id = doc.get(0).get("_id").toString();
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        NoSQLOperation operation = (NoSQLOperation) operations.get(0);

        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertEquals("No Command Detected", "insert", operation.getPayloadType());
        List<Object> queryData = new ArrayList<>();
        String string = String.format(
                "{ \"name\" : \"Mongo\", \"type\" : \"db\", \"count\" : 1, \"info\" : { \"x\" : 203, \"y\" : 102 }, \"_id\" : { \"$oid\" : \"%s\" } }", id);
        queryData.add(string);
        List<Object> expected = new ArrayList<>();
        expected.add(queryData);
        Assert.assertEquals("No data Found", queryData.toString(), operation.getPayload().toString());
    }

    @Test
    public void testInsert3()  {

        DB database = mongoClient.getDB("test");
        DBCollection mcollection = database.getCollection("test");
        DBObject doc1 = new BasicDBObject("name", "Mongo").append("type", "db").append("count", 1).append("info",
                new Document("x", 203).append("y", 102));
        List<DBObject> doc = new ArrayList<>();
        doc.add(doc1);
        mcollection.insert(doc, WriteConcern.ACKNOWLEDGED);
        String id = doc.get(0).get("_id").toString();
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        NoSQLOperation operation = (NoSQLOperation) operations.get(0);

        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertEquals("No Command Detected", "insert", operation.getPayloadType());
        List<Object> queryData = new ArrayList<>();
        String string = String.format(
                "{ \"name\" : \"Mongo\", \"type\" : \"db\", \"count\" : 1, \"info\" : { \"x\" : 203, \"y\" : 102 }, \"_id\" : { \"$oid\" : \"%s\" } }", id);
        queryData.add(string);
        List<Object> expected = new ArrayList<>();
        expected.add(queryData);
        Assert.assertEquals("No data Found", queryData.toString(), operation.getPayload().toString());
    }



    @Test
    public void testUpdate()  {

        DB database = mongoClient.getDB("test");
        DBCollection mcollection = database.getCollection("test");

        DBObject query = new BasicDBObject("name", "MongoDB");
        DBObject update = new BasicDBObject("type", "mongoose");
        mcollection.update(query, new BasicDBObject("$set",update));
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        NoSQLOperation operation = (NoSQLOperation) operations.get(0);

        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertEquals("No Command Detected", "update", operation.getPayloadType());
        List<Object> queryData = new ArrayList<>();
        queryData.add("{ \"$set\" : { \"type\" : \"mongoose\" } }, { \"name\" : \"MongoDB\" }");

        List<Object> expected = new ArrayList<>();
        expected.add(queryData);
        Assert.assertEquals("No data Found", queryData.toString(), operation.getPayload().toString());
    }

    @Test
    public void testUpdate1()  {

        DB database = mongoClient.getDB("test");
        DBCollection mcollection = database.getCollection("test");

        DBObject query = new BasicDBObject("name", "MongoDB");
        DBObject update = new BasicDBObject("type", "mongoose");
        mcollection.update(query, new BasicDBObject("$set",update), true, true);
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        NoSQLOperation operation = (NoSQLOperation) operations.get(0);

        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertEquals("No Command Detected", "update", operation.getPayloadType());
        List<Object> queryData = new ArrayList<>();
        queryData.add("{ \"$set\" : { \"type\" : \"mongoose\" } }, { \"name\" : \"MongoDB\" }");

        List<Object> expected = new ArrayList<>();
        expected.add(queryData);
        Assert.assertEquals("No data Found", queryData.toString(), operation.getPayload().toString());
    }

    @Test
    public void testUpdate2()  {

        DB database = mongoClient.getDB("test");
        DBCollection mcollection = database.getCollection("test");

        DBObject query = new BasicDBObject("name", "MongoDB");
        DBObject update = new BasicDBObject("type", "mongoose");
        mcollection.update(query, new BasicDBObject("$set",update), true, true, WriteConcern.ACKNOWLEDGED);
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        NoSQLOperation operation = (NoSQLOperation) operations.get(0);

        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertEquals("No Command Detected", "update", operation.getPayloadType());
        List<Object> queryData = new ArrayList<>();
        queryData.add("{ \"$set\" : { \"type\" : \"mongoose\" } }, { \"name\" : \"MongoDB\" }");

        List<Object> expected = new ArrayList<>();
        expected.add(queryData);
        Assert.assertEquals("No data Found", queryData.toString(), operation.getPayload().toString());
    }

    @Test
    public void testUpdateMulti()  {

        DB database = mongoClient.getDB("test");
        DBCollection mcollection = database.getCollection("test");

        DBObject query = new BasicDBObject("name", "MongoDB");
        DBObject update = new BasicDBObject("type", "mongoose");
        mcollection.updateMulti(query, new BasicDBObject("$set",update));

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        NoSQLOperation operation = (NoSQLOperation) operations.get(0);

        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertEquals("No Command Detected", "update", operation.getPayloadType());
        List<Object> queryData = new ArrayList<>();
        queryData.add("{ \"$set\" : { \"type\" : \"mongoose\" } }, { \"name\" : \"MongoDB\" }");

        List<Object> expected = new ArrayList<>();
        expected.add(queryData);
        Assert.assertEquals(queryData.toString(), operation.getPayload().toString());
    }

    @Test
    public void testSave()  {

        DB database = mongoClient.getDB("test");
        DBCollection mcollection = database.getCollection("test");
        DBObject dbo = new BasicDBObject("name", "MongoDB");
        mcollection.save(dbo);

        String id = dbo.get("_id").toString();
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        NoSQLOperation operation = (NoSQLOperation) operations.get(0);

        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertEquals("No Command Detected", "insert", operation.getPayloadType());
        List<Object> queryData = new ArrayList<>();
        String string = String.format("{ \"name\" : \"MongoDB\", \"_id\" : { \"$oid\" : \"%s\" } }", id);
        queryData.add(string);

        List<Object> expected = new ArrayList<>();
        expected.add(queryData);
        Assert.assertEquals("No data Found", queryData.toString(), operation.getPayload().toString());
    }

    @Test
    public void testGetCount()  {

        DB database = mongoClient.getDB("test");
        DBCollection mcollection = database.getCollection("test");

        mcollection.getCount();
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        NoSQLOperation operation = (NoSQLOperation) operations.get(0);

        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertEquals("No Command Detected", "count", operation.getPayloadType());
        List<Object> expected = new ArrayList<>();
        expected.add("{ }");


        Assert.assertEquals("No data Found", expected.toString(), operation.getPayload().toString());

    }

    @Test
    public void testGetCount1()  {

        DB database = mongoClient.getDB("test");
        DBCollection mcollection = database.getCollection("test");

        mcollection.getCount(new BasicDBObject("name", "MongoDB"));
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        NoSQLOperation operation = (NoSQLOperation) operations.get(0);

        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertEquals("No Command Detected", "count", operation.getPayloadType());
        List<Object> expected = new ArrayList<>();
        expected.add("{ \"name\" : \"MongoDB\" }");


        Assert.assertEquals("No data Found", expected.toString(), operation.getPayload().toString());
    }

    @Test
    public void testGetCount2()  {

        DB database = mongoClient.getDB("test");
        DBCollection mcollection = database.getCollection("test");

        mcollection.getCount(new BasicDBObject("name", "MongoDB"), new BasicDBObject("type", "db"));
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        NoSQLOperation operation = (NoSQLOperation) operations.get(0);

        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertEquals("No Command Detected", "count", operation.getPayloadType());
        List<Object> expected = new ArrayList<>();
        expected.add("{ \"name\" : \"MongoDB\" }");


        Assert.assertEquals("No data Found", expected.toString(), operation.getPayload().toString());
    }

    @Test
    public void testGetCount3()  {

        DB database = mongoClient.getDB("test");
        DBCollection mcollection = database.getCollection("test");

        mcollection.getCount(ReadPreference.primary());
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        NoSQLOperation operation = (NoSQLOperation) operations.get(0);

        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertEquals("No Command Detected", "count", operation.getPayloadType());
        List<Object> expected = new ArrayList<>();
        expected.add("{ }");


        Assert.assertEquals("No data Found", expected.toString(), operation.getPayload().toString());
    }

    @Test
    @Ignore("this testcase may fail, because this is not instrumented(RenameCollectionOperation).")
    public void testRename()  {

        DB database = mongoClient.getDB("test");
        DBCollection mcollection = database.getCollection("test");

        mcollection.rename("testDatabase");
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        NoSQLOperation operation = (NoSQLOperation) operations.get(0);

        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertEquals("No Command Detected", "rename", operation.getPayloadType());
        List<Object> expected = new ArrayList<>();
        expected.add("{ \"testDatabase\" }");


        Assert.assertEquals("No data Found", expected.toString(), operation.getPayload().toString());
    }

    @Test
    @Ignore("this testcase may fail, because this is not instrumented(ParallelCollectionScanOperation).")
    public void testParallelScan()  {

        DB database = mongoClient.getDB("test");
        DBCollection mcollection = database.getCollection("test");
        ParallelScanOptions parallelScanOptions = ParallelScanOptions
                .builder()
                .numCursors(4)
                .batchSize(1000)
                .build();
        mcollection.parallelScan(parallelScanOptions);
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        NoSQLOperation operation = (NoSQLOperation) operations.get(0);

        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertEquals("No Command Detected", "parallelScan", operation.getPayloadType());
        List<Object> expected = new ArrayList<>();
        expected.add("{ }");


        Assert.assertEquals("No data Found", expected.toString(), operation.getPayload().toString());
    }

    @Test
    @Ignore("this testcase may fail, because this is not instrumented(CreateIndexOperation).")
    public void testCreateIndex()  {

        DB database = mongoClient.getDB("test");
        DBCollection mcollection = database.getCollection("test");

        mcollection.createIndex("ind");
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        NoSQLOperation operation = (NoSQLOperation) operations.get(0);

        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertEquals("No Command Detected", "createIndex", operation.getPayloadType());
        List<Object> queryData = new ArrayList<>();
        queryData.add("{ \"ind\"}");

        List<Object> expected = new ArrayList<>();
        expected.add(queryData);
        Assert.assertEquals("No data Found", queryData.toString(), operation.getPayload().toString());
    }

    @Test
    @Ignore("this testcase may fail, because this is not instrumented(CreateIndexOperation)..")
    public void testCreateIndex1()  {

        DB database = mongoClient.getDB("test");
        DBCollection mcollection = database.getCollection("test");

        mcollection.createIndex(new BasicDBObject("name", "MongoDB"), "index");
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        NoSQLOperation operation = (NoSQLOperation) operations.get(0);

        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertEquals("No Command Detected", "createIndex", operation.getPayloadType());
        List<Object> queryData = new ArrayList<>();
        queryData.add("{ \"name\" : \"MongoDB\" }, { \"index\" }");

        List<Object> expected = new ArrayList<>();
        expected.add(queryData);
        Assert.assertEquals("No data Found", queryData.toString(), operation.getPayload().toString());
    }

    @Test
    @Ignore("this testcase may fail, because this is not instrumented(CreateIndexOperation)..")
    public void testCreateIndex2()  {

        DB database = mongoClient.getDB("test");
        DBCollection mcollection = database.getCollection("test");

        mcollection.createIndex(new BasicDBObject("name", "MongoDB"));
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        NoSQLOperation operation = (NoSQLOperation) operations.get(0);

        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertEquals("No Command Detected", "createIndex", operation.getPayloadType());
        List<Object> queryData = new ArrayList<>();
        queryData.add("{ \"name\" : \"MongoDB\" }");

        List<Object> expected = new ArrayList<>();
        expected.add(queryData);
        Assert.assertEquals("No data Found", queryData.toString(), operation.getPayload().toString());
    }

    @Test
    @Ignore("this testcase may fail, because this is not instrumented(DropCollectionOperation).")
    public void testDrop()  {

        DB database = mongoClient.getDB("test");
        DBCollection mcollection = database.getCollection("test");

        mcollection.drop();
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        NoSQLOperation operation = (NoSQLOperation) operations.get(0);

        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertEquals("No Command Detected", "drop", operation.getPayloadType());
        List<Object> expected = new ArrayList<>();
        expected.add("{ }");


        Assert.assertEquals("No data Found", expected.toString(), operation.getPayload().toString());
    }

    @Test
    @Ignore("this testcase may fail, because this is not instrumented(DropIndexOperation).")
    public void testDropIndex()  {

        DB database = mongoClient.getDB("test");
        DBCollection mcollection = database.getCollection("test");

        mcollection.dropIndex("ind");
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        NoSQLOperation operation = (NoSQLOperation) operations.get(0);

        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertEquals("No Command Detected", "dropIndex", operation.getPayloadType());
        List<Object> expected = new ArrayList<>();
        expected.add("{ \"ind\" }");


        Assert.assertEquals("No data Found", expected.toString(), operation.getPayload().toString());
    }
    @Test
    @Ignore("this testcase may fail, because it is not instrumented(DropIndexOperation)")
    public void testDropIndex1()  {

        DB database = mongoClient.getDB("test");
        DBCollection mcollection = database.getCollection("test");

        mcollection.dropIndex(new BasicDBObject("name",1));
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        NoSQLOperation operation = (NoSQLOperation) operations.get(0);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertEquals("No Command Detected", "dropIndex", operation.getPayloadType());
        List<Object> expected = new ArrayList<>();
        expected.add("{ \"ind\" }");

        Assert.assertEquals("No data Found", expected.toString(), operation.getPayload().toString());
    }
    @Test
    @Ignore("this testcase may fail, because it is not instrumented(DropIndexOperation)")
    public void testDropIndexes()  {

        DB database = mongoClient.getDB("test");
        DBCollection mcollection = database.getCollection("test");

        mcollection.dropIndexes();
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        NoSQLOperation operation = (NoSQLOperation) operations.get(0);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertEquals("No Command Detected", "dropIndex", operation.getPayloadType());
        List<Object> expected = new ArrayList<>();
        expected.add("{ \"ind\" }");

        Assert.assertEquals("No data Found", expected.toString(), operation.getPayload().toString());
    }
    @Test
    @Ignore("this testcase may fail, because it is not instrumented(DropIndexOperation)")
    public void testDropIndexes1()  {

        DB database = mongoClient.getDB("test");
        DBCollection mcollection = database.getCollection("test");

        mcollection.dropIndexes("index");
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        NoSQLOperation operation = (NoSQLOperation) operations.get(0);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertEquals("No Command Detected", "dropIndex", operation.getPayloadType());
        List<Object> expected = new ArrayList<>();
        expected.add("{ \"ind\" }");

        Assert.assertEquals("No data Found", expected.toString(), operation.getPayload().toString());
    }

}
