package com.nr.instrumentation.security.mongodb.operation;

import com.mongodb.DBObject;
import com.mongodb.MongoClient;
import com.mongodb.MongoNamespace;
import com.mongodb.client.ListCollectionsIterable;
import com.mongodb.client.ListIndexesIterable;
import com.mongodb.client.MapReduceIterable;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoDatabase;
import com.mongodb.client.MongoIterable;
import com.mongodb.client.model.BulkWriteOptions;
import com.mongodb.client.model.Filters;
import com.mongodb.client.model.FindOneAndDeleteOptions;
import com.mongodb.client.model.FindOneAndReplaceOptions;
import com.mongodb.client.model.FindOneAndUpdateOptions;
import com.mongodb.client.model.InsertOneModel;
import com.mongodb.client.model.RenameCollectionOptions;
import com.mongodb.client.model.Sorts;
import com.mongodb.client.model.UpdateOptions;
import com.mongodb.client.model.WriteModel;
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
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import static com.mongodb.client.model.Filters.eq;


@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = {"com.mongodb.operation","com.nr.agent.security.mongo"})
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
    public static void startMongo() throws IOException {
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
    public void testFindOneAndDelete()  {

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
        Assert.assertEquals("No data Found",queryData.toString(),operation.getPayload().toString());
    }
    @Test
    public void testFindOneAndDelete1()  {

        MongoDatabase database=  mongoClient.getDatabase("test");

        MongoCollection mcollection=database.getCollection("test");
        Bson query = eq("name", "MongoDB");
        FindOneAndDeleteOptions options = new FindOneAndDeleteOptions();
        options.sort(Sorts.descending("count"));
        mcollection.findOneAndDelete(query, options);
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        NoSQLOperation operation = (NoSQLOperation) operations.get(0);

        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertEquals("No Command Detected","findAndDelete",operation.getCommand());
        List<Object> queryData = new ArrayList<>();
        queryData.add("{ \"name\" : \"MongoDB\" }, { \"count\" : -1 }");

        List<Object> expected = new ArrayList<>();
        expected.add(queryData);
        Assert.assertEquals("No data Found",queryData.toString(),operation.getPayload().toString());
    }

    @Test
    public void testFindOneAndReplace()  {

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
        Assert.assertEquals("No data Found",queryData.toString(),operation.getPayload().toString());
    }
    @Test
    public void testFindOneAndReplace1()  {

        MongoDatabase database=  mongoClient.getDatabase("test");

        MongoCollection mcollection=database.getCollection("test");
        Bson query = eq("name", "MongoDB");
        Document doc = new Document("name", "Mongo").append("type", "db").append("count", 1).append("info",
                new Document("x", 203).append("y", 102));
        FindOneAndReplaceOptions options = new FindOneAndReplaceOptions();
        options.sort(Sorts.descending("count"));
        mcollection.findOneAndReplace(query,doc,options);
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        NoSQLOperation operation = (NoSQLOperation) operations.get(0);

        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertEquals("No Command Detected","findAndReplace",operation.getCommand());
        List<Object> queryData = new ArrayList<>();
        queryData.add("{ \"name\" : \"MongoDB\" }, { \"count\" : -1 }, { \"name\" : \"Mongo\", \"type\" : \"db\", \"count\" : 1, \"info\" : { \"x\" : 203, \"y\" : 102 } }");

        List<Object> expected = new ArrayList<>();
        expected.add(queryData);
        Assert.assertEquals("No data Found",queryData.toString(),operation.getPayload().toString());
    }
    @Test
    public void testFindOneAndUpdate()  {

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
        Assert.assertEquals("No data Found",queryData.toString(),operation.getPayload().toString());
    }

    @Test
    public void testFindOneAndUpdate1()  {

        MongoDatabase database=  mongoClient.getDatabase("test");

        MongoCollection mcollection=database.getCollection("test");
        Bson query = eq("name", "MongoDB");
        Bson update=eq("name","db");
        FindOneAndUpdateOptions options = new FindOneAndUpdateOptions();
        options.sort(Sorts.descending("count"));
        mcollection.findOneAndUpdate(query,update,options);
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        NoSQLOperation operation = (NoSQLOperation) operations.get(0);

        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertEquals("No Command Detected","findAndUpdate",operation.getCommand());
        List<Object> queryData = new ArrayList<>();
        queryData.add("{ \"name\" : \"MongoDB\" }, { \"count\" : -1 }, { \"name\" : \"db\" }");

        List<Object> expected = new ArrayList<>();
        expected.add(queryData);
        Assert.assertEquals("No data Found",queryData.toString(),operation.getPayload().toString());
    }
    @Test
    public void testUpdateOne()  {

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
        Assert.assertEquals("No Command Detected","write",operation.getCommand());
        List<Object> queryData = new ArrayList<>();
        queryData.add("{ \"$set\" : { \"type\" : \"db\" } }, { \"name\" : \"MongoDB\" }");

        List<Object> expected = new ArrayList<>();
        expected.add(queryData);
        Assert.assertEquals(queryData.toString(), operation.getPayload().toString());
    }
    @Test
    public void testUpdateOne1()  {

        MongoDatabase database=  mongoClient.getDatabase("test");

        MongoCollection mcollection=database.getCollection("test");
        Bson query = eq("name", "MongoDB");
        Document document = new Document("$set", new Document("type", "db"));
        UpdateOptions updateOptions = new UpdateOptions().upsert(true);
        mcollection.updateOne(query,document,updateOptions);
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        NoSQLOperation operation = (NoSQLOperation) operations.get(0);

        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertEquals("No Command Detected","write",operation.getCommand());
        List<Object> queryData = new ArrayList<>();
        queryData.add("{ \"$set\" : { \"type\" : \"db\" } }, { \"name\" : \"MongoDB\" }");

        List<Object> expected = new ArrayList<>();
        expected.add(queryData);
        Assert.assertEquals(queryData.toString(), operation.getPayload().toString());
    }
    @Test
    @Ignore("this test-case may fail because operation is not stored.")
    public void testListCollection()  {

        MongoDatabase database=  mongoClient.getDatabase("test");

        ListCollectionsIterable<DBObject> collections = database.listCollections(DBObject.class);
        for (DBObject collection : collections) {
            System.out.println(collection);
        }

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        NoSQLOperation operation = (NoSQLOperation) operations.get(0);

        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertEquals("No Command Detected","listCollections",operation.getCommand());
        List<Object> expected = new ArrayList<>();
        expected.add("{ }");


        Assert.assertEquals(expected.toString(), operation.getPayload().toString());
    }

    @Test
    @Ignore("this test-case may fail because operation is not stored.")
    public void testListCollection1()  {

        MongoDatabase database=  mongoClient.getDatabase("test");

        ListCollectionsIterable<Document> list = database.listCollections();
        for (Document name : list) {
            System.out.println(name);
        }

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        NoSQLOperation operation = (NoSQLOperation) operations.get(0);

        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertEquals("No Command Detected","listCollections",operation.getCommand());
        List<Object> expected = new ArrayList<>();
        expected.add("{ }");


        Assert.assertEquals(expected.toString(), operation.getPayload().toString());
    }

    @Test
    @Ignore("this test-case may fail because operation is not stored.")
    public void testListCollection2()  {

        MongoDatabase database=  mongoClient.getDatabase("test");

        MongoIterable<String> list = database.listCollectionNames();
        for (String name : list) {
            System.out.println(name);
        }

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        NoSQLOperation operation = (NoSQLOperation) operations.get(0);

        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertEquals("No Command Detected","listCollections",operation.getCommand());
        List<Object> expected = new ArrayList<>();
        expected.add("{ }");


        Assert.assertEquals(expected.toString(), operation.getPayload().toString());
    }

    @Test
    public void testUpdateMany()  {

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
        Assert.assertEquals("No Command Detected","write",operation.getCommand());
        List<Object> queryData = new ArrayList<>();
        queryData.add("{ \"$set\" : { \"type\" : \"db\" } }, { \"name\" : \"MongoDB\" }");

        List<Object> expected = new ArrayList<>();
        expected.add(queryData);
        Assert.assertEquals(queryData.toString(), operation.getPayload().toString());
    }
    @Test
    public void testUpdateMany1()  {

        MongoDatabase database=  mongoClient.getDatabase("test");

        MongoCollection mcollection=database.getCollection("test");

        Bson query = eq("name", "MongoDB");
        UpdateOptions updateOptions = new UpdateOptions().upsert(true);
        Document document = new Document("$set", new Document("type", "db"));
        mcollection.updateMany(query,document,updateOptions);
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        NoSQLOperation operation = (NoSQLOperation) operations.get(0);

        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertEquals("No Command Detected","write",operation.getCommand());
        List<Object> queryData = new ArrayList<>();
        queryData.add("{ \"$set\" : { \"type\" : \"db\" } }, { \"name\" : \"MongoDB\" }");

        List<Object> expected = new ArrayList<>();
        expected.add(queryData);
        Assert.assertEquals(queryData.toString(), operation.getPayload().toString());
    }
    @Test
    public void testInsertOne()  {

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
        Assert.assertEquals("No Command Detected","write",operation.getCommand());
        List<Object> queryData = new ArrayList<>();
        String string=String.format("{ \"name\" : \"Mongo\", \"type\" : \"db\", \"count\" : 1, \"info\" : { \"x\" : 203, \"y\" : 102 }, \"_id\" : { \"$oid\" : \"%s\" } }",id);
        queryData.add(string);
        List<Object> expected = new ArrayList<>();
        expected.add(queryData);
        Assert.assertEquals("No data Found",queryData.toString(),operation.getPayload().toString());
    }

    @Test
    public void testInsertMany()  {

        MongoDatabase database = mongoClient.getDatabase("test");
        MongoCollection mcollection = database.getCollection("test");
        Document document1 = new Document("name", "Ram").append("age", 26).append("city", "Hyderabad");

        List<Document> list = new ArrayList<Document>();
        list.add(document1);

        mcollection.insertMany(list);
        String id = list.get(0).get("_id").toString();
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        NoSQLOperation operation = (NoSQLOperation) operations.get(0);

        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertEquals("No Command Detected","write",operation.getCommand());
        List<Object> queryData = new ArrayList<>();
        String string=String.format("{ \"name\" : \"Ram\", \"age\" : 26, \"city\" : \"Hyderabad\", \"_id\" : { \"$oid\" : \"%s\" } }",id);
        queryData.add(string);
        List<Object> expected = new ArrayList<>();
        expected.add(queryData);
        Assert.assertEquals("No data Found",queryData.toString(),operation.getPayload().toString());
    }

    @Test
    @Ignore("this test case may fail.")
    public void testMapReduceWithInlineResults()  {

        MongoDatabase database = mongoClient.getDatabase("test");

        MongoCollection mcollection = database.getCollection("test");

        String map = "function(){emit(this.name, this.type)};";
        String reduce = "function(item,prev){prev.cnt+=1;}";
        MapReduceIterable mri= mcollection.mapReduce(map, reduce);
        if(mri!=null){
            for(Object o:mri){
                if(o!=null){
                    System.out.println(o);
                }
            }
        }
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
        Assert.assertEquals("No data Found", queryData.toString(), operation.getPayload().toString());
    }
    @Test
    public void testDeleteOne()  {

        MongoDatabase database = mongoClient.getDatabase("test");

        MongoCollection mcollection = database.getCollection("test");
        mcollection.deleteOne(Filters.eq("type", "Database"));
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        NoSQLOperation operation = (NoSQLOperation) operations.get(0);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertEquals("No Command Detected", "write", operation.getCommand());
        List<Object> queryData = new ArrayList<>();
        queryData.add("{ \"type\" : \"Database\" }");
        List<Object> expected = new ArrayList<>();
        expected.add(queryData);
        Assert.assertEquals("No data Found", queryData.toString(), operation.getPayload().toString());
    }

    @Test
    public void testDeleteMany()  {

        MongoDatabase database = mongoClient.getDatabase("test");

        MongoCollection mcollection = database.getCollection("test");
        mcollection.deleteMany(Filters.eq("type", "Database"));
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        NoSQLOperation operation = (NoSQLOperation) operations.get(0);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertEquals("No Command Detected", "write", operation.getCommand());
        List<Object> queryData = new ArrayList<>();
        queryData.add("{ \"type\" : \"Database\" }");
        List<Object> expected = new ArrayList<>();
        expected.add(queryData);
        Assert.assertEquals("No data Found", queryData.toString(), operation.getPayload().toString());
    }
    @Test
    public void testReplaceOne()  {

        MongoDatabase database=  mongoClient.getDatabase("test");

        MongoCollection mcollection=database.getCollection("test");

        Bson query = eq("name", "MongoDB");
        Document document = new Document("name","Mongo");
        mcollection.replaceOne(query,document);
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        NoSQLOperation operation = (NoSQLOperation) operations.get(0);

        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertEquals("No Command Detected","write",operation.getCommand());
        List<Object> queryData = new ArrayList<>();
        queryData.add("{ \"name\" : \"Mongo\" }, { \"name\" : \"MongoDB\" }");

        List<Object> expected = new ArrayList<>();
        expected.add(queryData);
        Assert.assertEquals(queryData.toString(), operation.getPayload().toString());
    }
    @Test
    public void testReplaceOne1()  {

        MongoDatabase database=  mongoClient.getDatabase("test");

        MongoCollection mcollection=database.getCollection("test");
        Bson query = eq("name", "MongoDB");
        Document document = new Document("name","Mongo");
        UpdateOptions updateOptions = new UpdateOptions().upsert(true);
        mcollection.replaceOne(query,document,updateOptions);
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        NoSQLOperation operation = (NoSQLOperation) operations.get(0);

        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertEquals("No Command Detected","write",operation.getCommand());
        List<Object> queryData = new ArrayList<>();
        queryData.add("{ \"name\" : \"Mongo\" }, { \"name\" : \"MongoDB\" }");

        List<Object> expected = new ArrayList<>();
        expected.add(queryData);
        Assert.assertEquals(queryData.toString(), operation.getPayload().toString());
    }
    @Test
    @Ignore("this test-case may fail because this is not instrumented(RenameCollectionOperation).")
    public void testRenameCollection()  {

        MongoDatabase database=  mongoClient.getDatabase("test");

        MongoCollection mcollection=database.getCollection("test");

        mcollection.renameCollection(new MongoNamespace("test","test"));
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        NoSQLOperation operation = (NoSQLOperation) operations.get(0);

        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertEquals("No Command Detected","write",operation.getCommand());
        List<Object> queryData = new ArrayList<>();
        queryData.add("{ \"name\" : \"Mongo\" }, { \"name\" : \"MongoDB\" }");

        List<Object> expected = new ArrayList<>();
        expected.add(queryData);
        Assert.assertEquals(queryData.toString(), operation.getPayload().toString());
    }
    @Test
    @Ignore("this test-case may fail because this is not instrumented(RenameCollectionOperation).")
    public void testRenameCollection1()  {

        MongoDatabase database=  mongoClient.getDatabase("test");

        MongoCollection mcollection=database.getCollection("test");
        RenameCollectionOptions renameOptions = new RenameCollectionOptions().dropTarget(true);
        mcollection.renameCollection(new MongoNamespace("test","test"),renameOptions);
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        NoSQLOperation operation = (NoSQLOperation) operations.get(0);

        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertEquals("No Command Detected","write",operation.getCommand());
        List<Object> queryData = new ArrayList<>();
        queryData.add("{ \"name\" : \"Mongo\" }, { \"name\" : \"MongoDB\" }");

        List<Object> expected = new ArrayList<>();
        expected.add(queryData);
        Assert.assertEquals(queryData.toString(), operation.getPayload().toString());
    }
    @Test
    @Ignore("this test case may fail, because this is not instrumented(ListIndexesOperation).")
    public void testListIndexes()  {

        MongoDatabase database=  mongoClient.getDatabase("test");

        MongoCollection mcollection=database.getCollection("test");

        ListIndexesIterable<Document> indexes = mcollection.listIndexes();
        for (Document index : indexes) {
            System.out.println(index.toJson());
        }


        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        NoSQLOperation operation = (NoSQLOperation) operations.get(0);

        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertEquals("No Command Detected","write",operation.getCommand());
        List<Object> queryData = new ArrayList<>();
        queryData.add("{ \"name\" : \"Mongo\" }, { \"name\" : \"MongoDB\" }");

        List<Object> expected = new ArrayList<>();
        expected.add(queryData);
        Assert.assertEquals(queryData.toString(), operation.getPayload().toString());
    }
    @Test
    @Ignore("this test case may fail, because this is not instrumented(ListIndexesOperation).")
    public void testListIndexes1()  {

        MongoDatabase database=  mongoClient.getDatabase("test");

        MongoCollection mcollection=database.getCollection("test");

        ListIndexesIterable<DBObject> indexes = mcollection.listIndexes(DBObject.class);
        for (DBObject index : indexes) {
            System.out.println(index);
        }
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        NoSQLOperation operation = (NoSQLOperation) operations.get(0);

        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertEquals("No Command Detected","write",operation.getCommand());
        List<Object> queryData = new ArrayList<>();
        queryData.add("{ \"name\" : \"Mongo\" }, { \"name\" : \"MongoDB\" }");

        List<Object> expected = new ArrayList<>();
        expected.add(queryData);
        Assert.assertEquals(queryData.toString(), operation.getPayload().toString());
    }

    @Test
    public void testBulkWrite()  {

        MongoDatabase database=  mongoClient.getDatabase("test");

        MongoCollection mcollection=database.getCollection("test");

        List<WriteModel<Document>> requests = new ArrayList<>();

        Document book1 = new Document("title", "The Great Gatsby")
                .append("author", "F. Scott Fitzgerald")
                .append("year", 1925);
        requests.add(new InsertOneModel<>(book1));

        mcollection.bulkWrite(requests);
        String id = book1.get("_id").toString();
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        NoSQLOperation operation = (NoSQLOperation) operations.get(0);

        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertEquals("No Command Detected","write",operation.getCommand());
        List<Object> queryData = new ArrayList<>();
        String string=String.format("{ \"title\" : \"The Great Gatsby\", \"author\" : \"F. Scott Fitzgerald\", \"year\" : 1925, \"_id\" : { \"$oid\" : \"%s\" } }",id);
        queryData.add(string);
        List<Object> expected = new ArrayList<>();
        expected.add(queryData);
        Assert.assertEquals("No data Found",queryData.toString(),operation.getPayload().toString());
    }

    @Test
    public void testBulkWrite1()  {

        MongoDatabase database=  mongoClient.getDatabase("test");

        MongoCollection mcollection=database.getCollection("test");

        List<WriteModel<Document>> requests = new ArrayList<>();

        Document book1 = new Document("title", "The Great Gatsby")
                .append("author", "F. Scott Fitzgerald")
                .append("year", 1925);
        requests.add(new InsertOneModel<>(book1));
        BulkWriteOptions options = new BulkWriteOptions().ordered(false);
        mcollection.bulkWrite(requests,options);
        String id = book1.get("_id").toString();
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        NoSQLOperation operation = (NoSQLOperation) operations.get(0);

        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertEquals("No Command Detected","write",operation.getCommand());
        List<Object> queryData = new ArrayList<>();
        String string=String.format("{ \"title\" : \"The Great Gatsby\", \"author\" : \"F. Scott Fitzgerald\", \"year\" : 1925, \"_id\" : { \"$oid\" : \"%s\" } }",id);
        queryData.add(string);
        List<Object> expected = new ArrayList<>();
        expected.add(queryData);
        Assert.assertEquals("No data Found",queryData.toString(),operation.getPayload().toString());
    }

}
