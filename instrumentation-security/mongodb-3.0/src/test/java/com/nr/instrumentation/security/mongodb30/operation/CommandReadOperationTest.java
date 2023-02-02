package com.nr.instrumentation.security.mongodb30.operation;

import com.mongodb.MongoClient;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoDatabase;
import com.mongodb.operation.CommandReadOperation;
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
import org.bson.BsonDocument;
import org.bson.BsonString;
import org.bson.Document;
import org.bson.codecs.Decoder;
import org.bson.codecs.configuration.CodecRegistries;
import org.bson.codecs.configuration.CodecRegistry;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = {"com.mongodb.operation","com.nr.agent.security.mongo"})
public class CommandReadOperationTest {

    private static final MongodStarter mongodStarter;
    private static MongodExecutable mongodExecutable;
    private static MongodProcess mongodProcess;
    private static MongoClient mongoClient;

    static {
        IRuntimeConfig runtimeConfig = new RuntimeConfigBuilder().defaults(Command.MongoD)
                .artifactStore(new ExtractedArtifactStoreBuilder()
                        .defaults(Command.MongoD)

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
    public static void startMongo() throws IOException {
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
    public void testExecute(){
        CodecRegistry codecRegistry = CodecRegistries.fromRegistries(
                MongoClient.getDefaultCodecRegistry(),
                CodecRegistries.fromCodecs(new DBPersonCodec())
        );

        Decoder<DBPerson> decoder = codecRegistry.get(
                DBPerson.class);
        BsonDocument document = new BsonDocument();
        document.put("name", new BsonString("MongoDB"));

        CommandReadOperation<DBPerson> cmd = new CommandReadOperation<DBPerson>("test", document, decoder);
        Document out = cmd.execute(null);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        NoSQLOperation operation = (NoSQLOperation) operations.get(0);

        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertEquals("No Command Detected", "read", operation.getCommand());
        List<Object> expected = new ArrayList<>();
        expected.add("{ \"name\" : \"MongoDB\" }");
        Assert.assertEquals("No data Found", expected.toString(), operation.getData().toString());
    }
    @Test
    public void testExecuteAsync(){
        CodecRegistry codecRegistry = CodecRegistries.fromRegistries(
                MongoClient.getDefaultCodecRegistry(),
                CodecRegistries.fromCodecs(new DBPersonCodec())
        );
        Decoder<DBPerson> decoder = codecRegistry.get(
                DBPerson.class);
        BsonDocument document = new BsonDocument();
        document.put("name", new BsonString("MongoDB"));

        CommandReadOperation<DBPerson> cmd = new CommandReadOperation<DBPerson>("test", document, decoder);
         cmd.executeAsync(null,(final DBPerson doc,final Throwable t)->{
             System.out.println("Ecexution completed");
        });

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        NoSQLOperation operation = (NoSQLOperation) operations.get(0);

        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertEquals("No Command Detected", "read", operation.getCommand());
        List<Object> expected = new ArrayList<>();
        expected.add("{ \"name\" : \"MongoDB\" }");
        Assert.assertEquals("No data Found", expected.toString(), operation.getData().toString());
    }
}
