package com.nr.instrumentation.security.mongodb.client.internal;

import com.mongodb.MongoClient;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoDatabase;
import com.mongodb.client.model.Filters;
import com.mongodb.client.model.Updates;
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
import org.bson.conversions.Bson;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;

import java.util.ArrayList;
import java.util.List;

import static com.mongodb.client.model.Filters.eq;
import static com.mongodb.client.model.Updates.set;

@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = {"com.mongodb.client.internal","com.nr.agent.security.mongo"})
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class OperationExecutorMongoDatabaseTest {

    private static final MongodStarter mongodStarter;

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


    private static MongodExecutable mongodExecutable;
    private static MongodProcess mongodProcess;
    private static MongoClient mongoClient;

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
        MongoDatabase database= mongoClient.getDatabase("test");
        database.createCollection("test");
        MongoCollection mcollection=database.getCollection("test");
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
    public void testFindOneAndDelete() throws Exception {

        MongoDatabase database=  mongoClient.getDatabase("test");

        MongoCollection mcollection=database.getCollection("test");
        Bson query = eq("name", "MongoDB");
        mcollection.findOneAndDelete(query);
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        NoSQLOperation operation = (NoSQLOperation) operations.get(0);

        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertEquals("No Command Detected","findAndDelete",operation.getCommand());
        List<Object> queryData = new ArrayList<>();
        queryData.add("{ \"name\" : \"MongoDB\" }");

        List<Object> expected = new ArrayList<>();
        expected.add(queryData);
        Assert.assertEquals("No data Found",expected.toString(),operation.getData().toString());
    }

    @Test
    public void testFindOneAndReplace() throws Exception {

        MongoDatabase database=  mongoClient.getDatabase("test");

        MongoCollection mcollection=database.getCollection("test");
        Bson query = eq("name", "MongoDB");
        Document doc = new Document("name", "Mongo").append("type", "db").append("count", 1).append("info",
                new Document("x", 203).append("y", 102));
        mcollection.findOneAndReplace(query,doc);
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        NoSQLOperation operation = (NoSQLOperation) operations.get(0);

        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertEquals("No Command Detected","findAndReplace",operation.getCommand());
        List<Object> queryData = new ArrayList<>();
        queryData.add("{ \"name\" : \"MongoDB\" }, { \"name\" : \"Mongo\", \"type\" : \"db\", \"count\" : 1, \"info\" : { \"x\" : 203, \"y\" : 102 } }");

        List<Object> expected = new ArrayList<>();
        expected.add(queryData);
        Assert.assertEquals("No data Found",expected.toString(),operation.getData().toString());
    }
    @Test
    public void testFindOneAndUpdate() throws Exception {

        MongoDatabase database=  mongoClient.getDatabase("test");

        MongoCollection mcollection=database.getCollection("test");
        Bson query = eq("name", "MongoDB");
        Bson update=eq("name","db");
        mcollection.findOneAndUpdate(query,update);
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        NoSQLOperation operation = (NoSQLOperation) operations.get(0);

        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertEquals("No Command Detected","findAndUpdate",operation.getCommand());
        List<Object> queryData = new ArrayList<>();
        queryData.add("{ \"name\" : \"MongoDB\" }, { \"name\" : \"db\" }");

        List<Object> expected = new ArrayList<>();
        expected.add(queryData);
        Assert.assertEquals("No data Found",expected.toString(),operation.getData().toString());
    }
    @Test
    //this testcase may fail, because it is instance of MixedBulkWriteOperation
    public void testUpdateOne() throws Exception {

        MongoDatabase database=  mongoClient.getDatabase("test");

        MongoCollection mcollection=database.getCollection("test");

        Bson query = eq("name", "MongoDB");
        Document document = new Document("$set", new Document("type", "db"));
        mcollection.updateOne(query,document);
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        NoSQLOperation operation = (NoSQLOperation) operations.get(0);

        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertEquals("No Command Detected","update",operation.getCommand());
        List<Object> queryData = new ArrayList<>();
        queryData.add("{ \"$set\" : { \"type\" : \"mongoose\" } }, { \"name\" : \"MongoDB\" }");

        List<Object> expected = new ArrayList<>();
        expected.add(queryData);
        Assert.assertEquals(expected.toString(), operation.getData().toString());
    }
    @Test
    //this testcase may fail, because it is instance of MixedBulkWriteOperation
    public void testListCollection() throws Exception {

        MongoDatabase database=  mongoClient.getDatabase("test");
        database.listCollections();
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        NoSQLOperation operation = (NoSQLOperation) operations.get(0);

        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertEquals("No Command Detected","listCollections",operation.getCommand());
        List<Object> expected = new ArrayList<>();
        expected.add("{ }");


        Assert.assertEquals(expected.toString(), operation.getData().toString());
    }
    @Test
    //this testcase may fail, because it is instance of MixedBulkWriteOperation
    public void testUpdateMany() throws Exception {

        MongoDatabase database=  mongoClient.getDatabase("test");

        MongoCollection mcollection=database.getCollection("test");

        Bson query = eq("name", "MongoDB");
        Document document = new Document("$set", new Document("type", "db"));
        mcollection.updateMany(query,document);
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        NoSQLOperation operation = (NoSQLOperation) operations.get(0);

        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertEquals("No Command Detected","update",operation.getCommand());
        List<Object> queryData = new ArrayList<>();
        queryData.add("{ \"$set\" : { \"type\" : \"db\" } }, { \"name\" : \"MongoDB\" }");

        List<Object> expected = new ArrayList<>();
        expected.add(queryData);
        Assert.assertEquals(expected.toString(), operation.getData().toString());
    }
    @Test
    //this testcase may fail, because it is instance of MixedBulkWriteOperation
    public void testInsertOne() throws Exception {

        MongoDatabase database = mongoClient.getDatabase("test");
        MongoCollection mcollection = database.getCollection("test");
        Document doc = new Document("name", "Mongo").append("type", "db").append("count", 1).append("info",
                new Document("x", 203).append("y", 102));

        mcollection.insertOne(doc);
        String id = doc.get("_id").toString();
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        NoSQLOperation operation = (NoSQLOperation) operations.get(0);

        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertEquals("No Command Detected","insert",operation.getCommand());
        List<Object> queryData = new ArrayList<>();
        String string=String.format("{ \"name\" : \"Mongo\", \"type\" : \"db\", \"count\" : 1, \"info\" : { \"x\" : 203, \"y\" : 102 }, \"_id\" : { \"$oid\" : \"%s\" } }",id);
        queryData.add(string);
        List<Object> expected = new ArrayList<>();
        expected.add(queryData);
        Assert.assertEquals("No data Found",expected.toString(),operation.getData().toString());
    }

    @Test
    //this testcase may fail, because it is instance of MixedBulkWriteOperation
    public void testInsertMany() throws Exception {

        MongoDatabase database = mongoClient.getDatabase("test");
        MongoCollection mcollection = database.getCollection("test");
        Document document1 = new Document("name", "Ram").append("age", 26).append("city", "Hyderabad");
        Document document2 = new Document("name", "Robert").append("age", 27).append("city", "Vishakhapatnam");
        Document document3 = new Document("name", "Rhim").append("age", 30).append("city", "Delhi");

        List<Document> list = new ArrayList<Document>();
        list.add(document1);
        list.add(document2);
        list.add(document3);

        mcollection.insertMany(list);
        String id = list.get(0).get("_id").toString();
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        NoSQLOperation operation = (NoSQLOperation) operations.get(0);

        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertEquals("No Command Detected","insert",operation.getCommand());
        List<Object> queryData = new ArrayList<>();
        String string=String.format("{ { \"name\" : \"Ram\", \"age\" : \"26\", \"city\" : \"Hyderabad\"}, { \"name\" : \"Robert\", \"age\" : \"27\", \"city\" : \"Vishakhapatnam\"}, { \"name\" : \"Rhim\", \"age\" : \"30\", \"city\" : \"Delhi\"}, \"_id\" : { \"$oid\" : \"%s\" } }",id);
        queryData.add(string);
        List<Object> expected = new ArrayList<>();
        expected.add(queryData);
        Assert.assertEquals("No data Found",expected.toString(),operation.getData().toString());
    }

}


