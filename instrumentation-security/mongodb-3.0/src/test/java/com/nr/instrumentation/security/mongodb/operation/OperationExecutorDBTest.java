package com.nr.instrumentation.security.mongodb.operation;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.mongodb.AggregationOptions;
import com.mongodb.BasicDBObject;
import com.mongodb.DB;
import com.mongodb.DBCollection;
import com.mongodb.DBObject;
import com.mongodb.MongoClient;
import com.mongodb.ParallelScanOptions;
import com.mongodb.ReadPreference;
import com.mongodb.WriteConcern;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoDatabase;
import com.mongodb.client.model.Filters;
import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.security.schema.operation.NoSQLOperation;
import de.flapdoodle.embed.mongo.Command;
import de.flapdoodle.embed.mongo.MongodExecutable;
import de.flapdoodle.embed.mongo.MongodProcess;
import de.flapdoodle.embed.mongo.MongodStarter;
import de.flapdoodle.embed.mongo.config.ExtractedArtifactStoreBuilder;
import de.flapdoodle.embed.mongo.config.IMongodConfig;
import de.flapdoodle.embed.mongo.config.MongodConfigBuilder;
import de.flapdoodle.embed.mongo.config.Net;
import de.flapdoodle.embed.mongo.config.RuntimeConfigBuilder;
import de.flapdoodle.embed.mongo.distribution.Version;
import de.flapdoodle.embed.process.config.IRuntimeConfig;
import de.flapdoodle.embed.process.extract.ITempNaming;
import de.flapdoodle.embed.process.runtime.Network;
import org.bson.Document;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = { "com.mongodb.operation", "com.nr.agent.security.mongo" })
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class OperationExecutorDBTest {
    private static final MongodStarter mongodStarter;
    private static MongodExecutable mongodExecutable;
    private static MongodProcess mongodProcess;
    private static MongoClient mongoClient;

    static {
        IRuntimeConfig runtimeConfig = new RuntimeConfigBuilder().defaults(Command.MongoD)
                .artifactStore(new ExtractedArtifactStoreBuilder()
                        .defaults(Command.MongoD)
                        // The default configuration creates executables whose names contain random UUIDs, which
                        // prompts repetitive firewall dialog popups. Instead, we use a naming strategy that
                        // produces a stable executable name and only have to acknowledge the firewall dialogs once.
                        // On macOS systems, the dialogs must be acknowledged quickly in order to be registered.
                        // Failure to click fast enough will result in additional dialogs on subsequent test runs.
                        // This firewall dialog issue only seems to occur with versions of mongo < 3.6.0
                        .executableNaming(new ITempNaming() {
                            @Override
                            public String nameFor(String prefix, String postfix) {
                                return prefix + "-Db310-" + postfix;
                            }
                        }))
                .build();
        mongodStarter = MongodStarter.getInstance(runtimeConfig);
    }

    @BeforeClass
    public static void startMongo() throws Exception {
        int port = Network.getFreeServerPort();
        IMongodConfig mongodConfig = new MongodConfigBuilder()
                .version(Version.V3_2_0)
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
    public void testRemove() throws Exception {

        DB database = mongoClient.getDB("test");
        DBCollection mcollection = database.getCollection("test");

        mcollection.remove(new BasicDBObject("name", "MongoDB"));
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        NoSQLOperation operation = (NoSQLOperation) operations.get(0);
        System.out.println(new ObjectMapper().writeValueAsString(operation));
//            Assert.assertEquals("Invalid executed parameters.", server.getEndPoint().toString(), operation.getArg());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertEquals("No Command Detected", "delete", operation.getCommand());

        List<Object> queryData = new ArrayList<>();
        queryData.add("{ \"name\" : \"MongoDB\" }");
        List<Object> expected = new ArrayList<>();
        expected.add(queryData);
        Assert.assertEquals("No data Found", expected.toString(), operation.getData().toString());
    }

    @Test
    public void testRemove1() throws Exception {

        DB database = mongoClient.getDB("test");
        DBCollection mcollection = database.getCollection("test");
        mcollection.remove(new BasicDBObject("name", "MongoDB"), WriteConcern.ACKNOWLEDGED);
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        NoSQLOperation operation = (NoSQLOperation) operations.get(0);
        System.out.println(new ObjectMapper().writeValueAsString(operation));
//            Assert.assertEquals("Invalid executed parameters.", server.getEndPoint().toString(), operation.getArg());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertEquals("No Command Detected", "delete", operation.getCommand());
        List<Object> queryData = new ArrayList<>();
        queryData.add("{ \"name\" : \"MongoDB\" }");
        List<Object> expected = new ArrayList<>();
        expected.add(queryData);
        Assert.assertEquals("No data Found", expected.toString(), operation.getData().toString());
    }

    @Test
    public void testAggregate() throws Exception {

        DB database = mongoClient.getDB("test");
        DBCollection mcollection = database.getCollection("test");
        DBObject fields = new BasicDBObject("type", 1);
        fields.put("attack", 1);
        fields.put("defense", 1);
        DBObject project = new BasicDBObject("$project", fields);
        List<DBObject> pipeline = Collections.singletonList(project);
        mcollection.aggregate(pipeline);
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        NoSQLOperation operation = (NoSQLOperation) operations.get(0);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertEquals("No Command Detected", "aggregate", operation.getCommand());
        List<Object> queryData = new ArrayList<>();
        queryData.add("{ \"$project\" : { \"type\" : 1, \"attack\" : 1, \"defense\" : 1 } }");
        List<Object> expected = new ArrayList<>();
        expected.add(queryData);
        Assert.assertEquals("No data Found", expected.toString(), operation.getData().toString());
    }

    @Test
    public void testAggregate1() throws Exception {

        DB database = mongoClient.getDB("test");
        DBCollection mcollection = database.getCollection("test");
        DBObject fields = new BasicDBObject("type", 1);
        fields.put("attack", 1);
        fields.put("defense", 1);
        DBObject project = new BasicDBObject("$project", fields);
        List<DBObject> pipeline = Collections.singletonList(project);
        mcollection.aggregate(pipeline, ReadPreference.primary());
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        NoSQLOperation operation = (NoSQLOperation) operations.get(0);
//            Assert.assertEquals("Invalid executed parameters.", server.getEndPoint().toString(), operation.getArg());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertEquals("No Command Detected", "aggregate", operation.getCommand());
        List<Object> queryData = new ArrayList<>();
        queryData.add("{ \"$project\" : { \"type\" : 1, \"attack\" : 1, \"defense\" : 1 } }");
        List<Object> expected = new ArrayList<>();
        expected.add(queryData);
        Assert.assertEquals("No data Found", expected.toString(), operation.getData().toString());
    }

    @Test
    public void testAggregate2() throws Exception {

        DB database = mongoClient.getDB("test");
        DBCollection mcollection = database.getCollection("test");
        DBObject fields = new BasicDBObject("type", 1);
        fields.put("attack", 1);
        fields.put("defense", 1);
        DBObject project = new BasicDBObject("$project", fields);
        List<DBObject> pipeline = Collections.singletonList(project);
        AggregationOptions aggregationOptions = AggregationOptions.builder().batchSize(100)
                .outputMode(AggregationOptions.OutputMode.CURSOR).allowDiskUse(true).build();
        mcollection.aggregate(pipeline, aggregationOptions);
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        NoSQLOperation operation = (NoSQLOperation) operations.get(0);

        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertEquals("No Command Detected", "aggregate", operation.getCommand());
        List<Object> queryData = new ArrayList<>();
        queryData.add("{ \"$project\" : { \"type\" : 1, \"attack\" : 1, \"defense\" : 1 } }");
        List<Object> expected = new ArrayList<>();
        expected.add(queryData);
        Assert.assertEquals("No data Found", expected.toString(), operation.getData().toString());
    }

    @Test
    public void testAggregate3() throws Exception {

        DB database = mongoClient.getDB("test");
        DBCollection mcollection = database.getCollection("test");
        DBObject fields = new BasicDBObject("type", 1);
        fields.put("attack", 1);
        fields.put("defense", 1);
        DBObject project = new BasicDBObject("$project", fields);
        List<DBObject> pipeline = Collections.singletonList(project);
        AggregationOptions aggregationOptions = AggregationOptions.builder().batchSize(100)
                .outputMode(AggregationOptions.OutputMode.CURSOR).allowDiskUse(true).build();
        mcollection.aggregate(pipeline, aggregationOptions, ReadPreference.primary());
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        NoSQLOperation operation = (NoSQLOperation) operations.get(0);

//            Assert.assertEquals("Invalid executed parameters.", server.getEndPoint().toString(), operation.getArg());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertEquals("No Command Detected", "aggregate", operation.getCommand());
        List<Object> queryData = new ArrayList<>();
        queryData.add("{ \"$project\" : { \"type\" : 1, \"attack\" : 1, \"defense\" : 1 } }");
        List<Object> expected = new ArrayList<>();
        expected.add(queryData);
        Assert.assertEquals("No data Found", expected.toString(), operation.getData().toString());
    }

    @Test
    public void testCount() throws Exception {

        DB database = mongoClient.getDB("test");
        DBCollection mcollection = database.getCollection("test");

        mcollection.count();
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        NoSQLOperation operation = (NoSQLOperation) operations.get(0);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertEquals("No Command Detected", "count", operation.getCommand());
        List<Object> expected = new ArrayList<>();
        expected.add("{ }");
        Assert.assertEquals("No data Found", expected.toString(), operation.getData().toString());
    }

    @Test
    public void testCount1() throws Exception {

        DB database = mongoClient.getDB("test");
        DBCollection mcollection = database.getCollection("test");

        mcollection.count(new BasicDBObject("name", "MongoDB"));
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        NoSQLOperation operation = (NoSQLOperation) operations.get(0);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertEquals("No Command Detected", "count", operation.getCommand());
        List<Object> expected = new ArrayList<>();
        expected.add("{ \"name\" : \"MongoDB\" }");

        Assert.assertEquals("No data Found", expected.toString(), operation.getData().toString());
    }

    @Test
    public void testCount2() throws Exception {

        DB database = mongoClient.getDB("test");
        DBCollection mcollection = database.getCollection("test");

        mcollection.count(new BasicDBObject("name", "MongoDB"), ReadPreference.primary());
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        NoSQLOperation operation = (NoSQLOperation) operations.get(0);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertEquals("No Command Detected", "count", operation.getCommand());
        List<Object> expected = new ArrayList<>();
        expected.add("{ \"name\" : \"MongoDB\" }");

        Assert.assertEquals("No data Found", expected.toString(), operation.getData().toString());
    }

    @Test
    public void testDistinct() throws Exception {

        DB database = mongoClient.getDB("test");
        DBCollection mcollection = database.getCollection("test");

        mcollection.distinct("name");
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        NoSQLOperation operation = (NoSQLOperation) operations.get(0);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertEquals("No Command Detected", "distinct", operation.getCommand());
        List<Object> expected = new ArrayList<>();
        expected.add("{ }");
        Assert.assertEquals("No data Found", expected.toString(), operation.getData().toString());
    }

    @Test
    public void testDistinct1() throws Exception {

        DB database = mongoClient.getDB("test");
        DBCollection mcollection = database.getCollection("test");

        mcollection.distinct("name", ReadPreference.primary());
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        NoSQLOperation operation = (NoSQLOperation) operations.get(0);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertEquals("No Command Detected", "distinct", operation.getCommand());
        List<Object> expected = new ArrayList<>();
        expected.add("{ }");
        Assert.assertEquals("No data Found", expected.toString(), operation.getData().toString());
    }

    @Test
    public void testDistinct2() throws Exception {

        DB database = mongoClient.getDB("test");
        DBCollection mcollection = database.getCollection("test");

        mcollection.distinct("name", new BasicDBObject("type", "Database"));
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        NoSQLOperation operation = (NoSQLOperation) operations.get(0);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertEquals("No Command Detected", "distinct", operation.getCommand());
        List<Object> expected = new ArrayList<>();
        expected.add("{ \"type\" : \"Database\" }");
        Assert.assertEquals("No data Found", expected.toString(), operation.getData().toString());
    }

    @Test
    public void testFindAndRemove() throws Exception {

        DB database = mongoClient.getDB("test");

        DBCollection mcollection = database.getCollection("test");

        mcollection.findAndRemove(new BasicDBObject("name", "MongoDB"));
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        NoSQLOperation operation = (NoSQLOperation) operations.get(0);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertEquals("No Command Detected", "findAndDelete", operation.getCommand());
        List<Object> queryData = new ArrayList<>();
        queryData.add("{ \"name\" : \"MongoDB\" }");
        List<Object> expected = new ArrayList<>();
        expected.add(queryData);
        Assert.assertEquals("No data Found", expected.toString(), operation.getData().toString());
    }

    @Test
    public void testFindAndModify() throws Exception {

        DB database = mongoClient.getDB("test");

        DBCollection mcollection = database.getCollection("test");

        mcollection.findAndModify(new BasicDBObject("name", "MongoDB"), new BasicDBObject("type", "db"));
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        NoSQLOperation operation = (NoSQLOperation) operations.get(0);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertEquals("No Command Detected", "findAndReplace", operation.getCommand());
        List<Object> queryData = new ArrayList<>();
        queryData.add("{ \"name\" : \"MongoDB\" }, { \"type\" : \"db\" }");
        List<Object> expected = new ArrayList<>();
        expected.add(queryData);
        Assert.assertEquals("No data Found", expected.toString(), operation.getData().toString());
    }

    @Test
    //this testcase may fail, because it is instance of MixedBulkWriteOperation
    public void testFind() throws Exception {

        DB database = mongoClient.getDB("test");
        DBCollection mcollection = database.getCollection("test");
        DBObject query = new BasicDBObject("name", "MongoDB");
        mcollection.find(query);
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        NoSQLOperation operation = (NoSQLOperation) operations.get(0);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertEquals("No Command Detected", "find", operation.getCommand());
        List<Object> queryData = new ArrayList<>();
        queryData.add("{ \"name\" : \"MongoDB\" }");
        List<Object> expected = new ArrayList<>();
        expected.add(queryData);
        Assert.assertEquals("No data Found", expected.toString(), operation.getData().toString());
    }

    @Test
    //this testcase may fail, because it is instance of MixedBulkWriteOperation
    public void testFind1() throws Exception {

        DB database = mongoClient.getDB("test");
        DBCollection mcollection = database.getCollection("test");

        mcollection.find();
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        NoSQLOperation operation = (NoSQLOperation) operations.get(0);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertEquals("No Command Detected", "find", operation.getCommand());
        List<Object> expected = new ArrayList<>();
        expected.add("{ }");

        Assert.assertEquals("No data Found", expected.toString(), operation.getData().toString());
    }

    @Test
    //this testcase may fail, because it is instance of MixedBulkWriteOperation
    public void testFind2() throws Exception {

        DB database = mongoClient.getDB("test");
        DBCollection mcollection = database.getCollection("test");
        DBObject query = new BasicDBObject("name", "MongoDB");
        mcollection.find(query, new BasicDBObject("type", "db"));
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        NoSQLOperation operation = (NoSQLOperation) operations.get(0);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertEquals("No Command Detected", "find", operation.getCommand());
        List<Object> queryData = new ArrayList<>();
        queryData.add("{ \"name\" : \"MongoDB\" }");
        List<Object> expected = new ArrayList<>();
        expected.add(queryData);
        Assert.assertEquals("No data Found", expected.toString(), operation.getData().toString());
    }

    @Test
    public void testFindOne() throws Exception {

        DB database = mongoClient.getDB("test");
        DBCollection mcollection = database.getCollection("test");
        mcollection.findOne();
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        NoSQLOperation operation = (NoSQLOperation) operations.get(0);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertEquals("No Command Detected", "find", operation.getCommand());
        List<Object> expected = new ArrayList<>();
        expected.add("{ }");
        Assert.assertEquals("No data Found", expected.toString(), operation.getData().toString());
    }

    @Test
    public void testFindOne1() throws Exception {

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
        Assert.assertEquals("No Command Detected", "find", operation.getCommand());
        List<Object> expected = new ArrayList<>();
        expected.add("{ \"name\" : \"MongoDB\" }");

        Assert.assertEquals("No data Found", expected.toString(), operation.getData().toString());
    }

    @Test
    public void testFindOne2() throws Exception {

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
        Assert.assertEquals("No Command Detected", "find", operation.getCommand());
        List<Object> expected = new ArrayList<>();
        expected.add("{ \"name\" : \"MongoDB\" }");

        Assert.assertEquals("No data Found", expected.toString(), operation.getData().toString());
    }

    @Test
    public void testGroup() throws Exception {

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
        Assert.assertEquals("No Command Detected", "Group", operation.getCommand());
        List<Object> queryData = new ArrayList<>();
        queryData.add("{ \"name\" : \"MongoDB\" }");
        List<Object> expected = new ArrayList<>();
        expected.add(queryData);
        Assert.assertEquals("No data Found", expected.toString(), operation.getData().toString());
    }

    @Test
    //this testcase may fail, because it is instance of MixedBulkWriteOperation
    public void testMapReduceWithInlineResults() throws Exception {

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
        Assert.assertEquals("No Command Detected", "mapReduce", operation.getCommand());
        List<Object> queryData = new ArrayList<>();
        queryData.add("{ \"name\" : \"MongoDB\" }");
        List<Object> expected = new ArrayList<>();
        expected.add(queryData);
        Assert.assertEquals("No data Found", expected.toString(), operation.getData().toString());
    }

    @Test
    //this testcase may fail, because it is instance of MixedBulkWriteOperation
    public void testDeleteOne() throws Exception {

        MongoDatabase database = mongoClient.getDatabase("test");

        MongoCollection mcollection = database.getCollection("test");
        mcollection.deleteOne(Filters.eq("type", "Database"));
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        NoSQLOperation operation = (NoSQLOperation) operations.get(0);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertEquals("No Command Detected", "delete", operation.getCommand());
        List<Object> queryData = new ArrayList<>();
        queryData.add("{ \"type\" : \"Database\" }");
        List<Object> expected = new ArrayList<>();
        expected.add(queryData);
        Assert.assertEquals("No data Found", expected.toString(), operation.getData().toString());
    }

    @Test
    public void testInsert() throws Exception {

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
        Assert.assertEquals("No Command Detected", "insert", operation.getCommand());
        List<Object> queryData = new ArrayList<>();
        String string = String.format("{ \"name\" : \"db\", \"_id\" : { \"$oid\" : \"%s\" } }", id);
        queryData.add(string);
        List<Object> expected = new ArrayList<>();
        expected.add(queryData);
        Assert.assertEquals("No data Found", expected.toString(), operation.getData().toString());
    }

    @Test
    public void testInsert1() throws Exception {

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
        Assert.assertEquals("No Command Detected", "insert", operation.getCommand());
        List<Object> queryData = new ArrayList<>();
        String string = String.format("{ \"name\" : \"db\", \"_id\" : { \"$oid\" : \"%s\" } }", id);
        queryData.add(string);
        List<Object> expected = new ArrayList<>();
        expected.add(queryData);
        Assert.assertEquals("No data Found", expected.toString(), operation.getData().toString());
    }

    @Test
    public void testInsert2() throws Exception {

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
        Assert.assertEquals("No Command Detected", "insert", operation.getCommand());
        List<Object> queryData = new ArrayList<>();
        String string = String.format(
                "{ \"name\" : \"Mongo\", \"type\" : \"db\", \"count\" : 1, \"info\" : { \"x\" : 203, \"y\" : 102 }, \"_id\" : { \"$oid\" : \"%s\" } }", id);
        queryData.add(string);
        List<Object> expected = new ArrayList<>();
        expected.add(queryData);
        Assert.assertEquals("No data Found", expected.toString(), operation.getData().toString());
    }

    @Test
    public void testInsert3() throws Exception {

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
        Assert.assertEquals("No Command Detected", "insert", operation.getCommand());
        List<Object> queryData = new ArrayList<>();
        String string = String.format(
                "{ \"name\" : \"Mongo\", \"type\" : \"db\", \"count\" : 1, \"info\" : { \"x\" : 203, \"y\" : 102 }, \"_id\" : { \"$oid\" : \"%s\" } }", id);
        queryData.add(string);
        List<Object> expected = new ArrayList<>();
        expected.add(queryData);
        Assert.assertEquals("No data Found", expected.toString(), operation.getData().toString());
    }

    @Test
    //this testcase may fail, because it is instance of MixedBulkWriteOperation
    public void testMapReduceToCollection() throws Exception {

        MongoDatabase database = mongoClient.getDatabase("test");

        MongoCollection mcollection = database.getCollection("test");

        String map = "function(){emit(this.name, this.type)};";
        String reduce = "function(item,prev){prev.cnt+=1;}";
        mcollection.mapReduce(map, reduce);
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        NoSQLOperation operation = (NoSQLOperation) operations.get(0);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertEquals("No Command Detected", "mapReduce", operation.getCommand());
        List<Object> queryData = new ArrayList<>();
        queryData.add("{ \"function(){emit(this.name, this.type)};\" : \"function(item,prev){prev.cnt+=1;}\" }");
        List<Object> expected = new ArrayList<>();
        expected.add(queryData);
        Assert.assertEquals("No data Found", expected.toString(), operation.getData().toString());
    }

    @Test
    public void testUpdate() throws Exception {

        DB database = mongoClient.getDB("test");
        DBCollection mcollection = database.getCollection("test");

        DBObject query = new BasicDBObject("name", "MongoDB");
        DBObject update = new BasicDBObject("type", "mongoose");
        mcollection.update(query, update);
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        NoSQLOperation operation = (NoSQLOperation) operations.get(0);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertEquals("No Command Detected", "update", operation.getCommand());
        List<Object> queryData = new ArrayList<>();
        queryData.add("{ \"type\" : \"mongoose\" }, { \"name\" : \"MongoDB\" }");
        List<Object> expected = new ArrayList<>();
        expected.add(queryData);
        Assert.assertEquals("No data Found", expected.toString(), operation.getData().toString());
    }

    @Test
    public void testUpdate1() throws Exception {

        DB database = mongoClient.getDB("test");
        DBCollection mcollection = database.getCollection("test");

        DBObject query = new BasicDBObject("name", "MongoDB");
        DBObject update = new BasicDBObject("type", "mongoose");
        mcollection.update(query, update, true, true);
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        NoSQLOperation operation = (NoSQLOperation) operations.get(0);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertEquals("No Command Detected", "update", operation.getCommand());
        List<Object> queryData = new ArrayList<>();
        queryData.add("{ \"type\" : \"mongoose\" }, { \"name\" : \"MongoDB\" }");
        List<Object> expected = new ArrayList<>();
        expected.add(queryData);
        Assert.assertEquals("No data Found", expected.toString(), operation.getData().toString());
    }

    @Test
    public void testUpdate2() throws Exception {

        DB database = mongoClient.getDB("test");
        DBCollection mcollection = database.getCollection("test");

        DBObject query = new BasicDBObject("name", "MongoDB");
        DBObject update = new BasicDBObject("type", "mongoose");
        mcollection.update(query, update, true, true, WriteConcern.ACKNOWLEDGED);
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        NoSQLOperation operation = (NoSQLOperation) operations.get(0);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertEquals("No Command Detected", "update", operation.getCommand());
        List<Object> queryData = new ArrayList<>();
        queryData.add("{ \"type\" : \"mongoose\" }, { \"name\" : \"MongoDB\" }");
        List<Object> expected = new ArrayList<>();
        expected.add(queryData);
        Assert.assertEquals("No data Found", expected.toString(), operation.getData().toString());
    }

    @Test
    public void testUpdateMulti() throws Exception {

        DB database = mongoClient.getDB("test");
        DBCollection mcollection = database.getCollection("test");

        DBObject query = new BasicDBObject("name", "MongoDB");
        DBObject update = new BasicDBObject("type", "mongoose");
        mcollection.updateMulti(query, update);
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        NoSQLOperation operation = (NoSQLOperation) operations.get(0);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertEquals("No Command Detected", "update", operation.getCommand());
        List<Object> queryData = new ArrayList<>();
        queryData.add("{ \"type\" : \"mongoose\" }, { \"name\" : \"MongoDB\" }");
        List<Object> expected = new ArrayList<>();
        expected.add(queryData);
        Assert.assertEquals(expected.toString(), operation.getData().toString());
    }

    @Test
    public void testSave() throws Exception {

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
        Assert.assertEquals("No Command Detected", "insert", operation.getCommand());
        List<Object> queryData = new ArrayList<>();
        String string = String.format("{ \"name\" : \"MongoDB\", \"_id\" : { \"$oid\" : \"%s\" } }", id);
        queryData.add(string);
        List<Object> expected = new ArrayList<>();
        expected.add(queryData);
        Assert.assertEquals("No data Found", expected.toString(), operation.getData().toString());
    }

    @Test
    public void testGetCount() throws Exception {

        DB database = mongoClient.getDB("test");
        DBCollection mcollection = database.getCollection("test");

        mcollection.getCount();
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        NoSQLOperation operation = (NoSQLOperation) operations.get(0);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertEquals("No Command Detected", "count", operation.getCommand());
        List<Object> expected = new ArrayList<>();
        expected.add("{ }");

        Assert.assertEquals("No data Found", expected.toString(), operation.getData().toString());
    }

    @Test
    public void testGetCount1() throws Exception {

        DB database = mongoClient.getDB("test");
        DBCollection mcollection = database.getCollection("test");

        mcollection.getCount(new BasicDBObject("name", "MongoDB"));
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        NoSQLOperation operation = (NoSQLOperation) operations.get(0);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertEquals("No Command Detected", "count", operation.getCommand());
        List<Object> expected = new ArrayList<>();
        expected.add("{ \"name\" : \"MongoDB\" }");

        Assert.assertEquals("No data Found", expected.toString(), operation.getData().toString());
    }

    @Test
    public void testGetCount2() throws Exception {

        DB database = mongoClient.getDB("test");
        DBCollection mcollection = database.getCollection("test");

        mcollection.getCount(new BasicDBObject("name", "MongoDB"), new BasicDBObject("type", "db"));
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        NoSQLOperation operation = (NoSQLOperation) operations.get(0);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertEquals("No Command Detected", "count", operation.getCommand());
        List<Object> expected = new ArrayList<>();
        expected.add("{ \"name\" : \"MongoDB\" }");

        Assert.assertEquals("No data Found", expected.toString(), operation.getData().toString());
    }

    @Test
    public void testGetCount3() throws Exception {

        DB database = mongoClient.getDB("test");
        DBCollection mcollection = database.getCollection("test");

        mcollection.getCount(ReadPreference.primary());
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        NoSQLOperation operation = (NoSQLOperation) operations.get(0);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertEquals("No Command Detected", "count", operation.getCommand());
        List<Object> expected = new ArrayList<>();
        expected.add("{ }");

        Assert.assertEquals("No data Found", expected.toString(), operation.getData().toString());
    }

    @Test
    //this testcase may fail, because it is instance of MixedBulkWriteOperation
    public void testRename() throws Exception {

        DB database = mongoClient.getDB("test");
        DBCollection mcollection = database.getCollection("test");

        mcollection.rename("testDatabase");
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        NoSQLOperation operation = (NoSQLOperation) operations.get(0);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertEquals("No Command Detected", "rename", operation.getCommand());
        List<Object> expected = new ArrayList<>();
        expected.add("{ \"testDatabase\" }");

        Assert.assertEquals("No data Found", expected.toString(), operation.getData().toString());
    }

    @Test
    //this testcase may fail, because it is instance of MixedBulkWriteOperation
    public void testParallelScan() throws Exception {

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
        Assert.assertEquals("No Command Detected", "parallelScan", operation.getCommand());
        List<Object> expected = new ArrayList<>();
        expected.add("{ }");

        Assert.assertEquals("No data Found", expected.toString(), operation.getData().toString());
    }

    @Test
    //this testcase may fail, because it is instance of MixedBulkWriteOperation
    public void testCreateIndex() throws Exception {

        DB database = mongoClient.getDB("test");
        DBCollection mcollection = database.getCollection("test");

        mcollection.createIndex("ind");
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        NoSQLOperation operation = (NoSQLOperation) operations.get(0);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertEquals("No Command Detected", "createIndex", operation.getCommand());
        List<Object> queryData = new ArrayList<>();
        queryData.add("{ \"ind\"}");
        List<Object> expected = new ArrayList<>();
        expected.add(queryData);
        Assert.assertEquals("No data Found", expected.toString(), operation.getData().toString());
    }

    @Test
    //this testcase may fail, because it is instance of MixedBulkWriteOperation
    public void testCreateIndex1() throws Exception {

        DB database = mongoClient.getDB("test");
        DBCollection mcollection = database.getCollection("test");

        mcollection.createIndex(new BasicDBObject("name", "MongoDB"), "index");
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        NoSQLOperation operation = (NoSQLOperation) operations.get(0);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertEquals("No Command Detected", "createIndex", operation.getCommand());
        List<Object> queryData = new ArrayList<>();
        queryData.add("{ \"name\" : \"MongoDB\" }, { \"index\" }");
        List<Object> expected = new ArrayList<>();
        expected.add(queryData);
        Assert.assertEquals("No data Found", expected.toString(), operation.getData().toString());
    }

    @Test
    //this testcase may fail, because it is instance of MixedBulkWriteOperation
    public void testCreateIndex2() throws Exception {

        DB database = mongoClient.getDB("test");
        DBCollection mcollection = database.getCollection("test");

        mcollection.createIndex(new BasicDBObject("name", "MongoDB"));
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        NoSQLOperation operation = (NoSQLOperation) operations.get(0);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertEquals("No Command Detected", "createIndex", operation.getCommand());
        List<Object> queryData = new ArrayList<>();
        queryData.add("{ \"name\" : \"MongoDB\" }");
        List<Object> expected = new ArrayList<>();
        expected.add(queryData);
        Assert.assertEquals("No data Found", expected.toString(), operation.getData().toString());
    }

    @Test
    //this testcase may fail, because it is instance of MixedBulkWriteOperation
    public void testDrop() throws Exception {

        DB database = mongoClient.getDB("test");
        DBCollection mcollection = database.getCollection("test");

        mcollection.drop();
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        NoSQLOperation operation = (NoSQLOperation) operations.get(0);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertEquals("No Command Detected", "drop", operation.getCommand());
        List<Object> expected = new ArrayList<>();
        expected.add("{ }");

        Assert.assertEquals("No data Found", expected.toString(), operation.getData().toString());
    }

    @Test
    //this testcase may fail, because it is instance of MixedBulkWriteOperation
    public void testDropIndex() throws Exception {

        DB database = mongoClient.getDB("test");
        DBCollection mcollection = database.getCollection("test");

        mcollection.dropIndex("ind");
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        NoSQLOperation operation = (NoSQLOperation) operations.get(0);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertEquals("No Command Detected", "dropIndex", operation.getCommand());
        List<Object> expected = new ArrayList<>();
        expected.add("{ \"ind\" }");

        Assert.assertEquals("No data Found", expected.toString(), operation.getData().toString());
    }

}
