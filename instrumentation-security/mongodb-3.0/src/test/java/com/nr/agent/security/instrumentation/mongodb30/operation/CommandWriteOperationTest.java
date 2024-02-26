package com.nr.agent.security.instrumentation.mongodb30.operation;

import com.mongodb.DBObject;
import com.mongodb.MongoClient;
import com.mongodb.MongoClientOptions;
import com.mongodb.ReadPreference;
import com.mongodb.ServerAddress;
import com.mongodb.binding.AsyncClusterBinding;
import com.mongodb.binding.ClusterBinding;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoDatabase;

import com.mongodb.connection.Cluster;
import com.mongodb.connection.ClusterSettings;
import com.mongodb.connection.ConnectionPoolSettings;
import com.mongodb.connection.DefaultClusterFactory;
import com.mongodb.connection.ServerSettings;
import com.mongodb.connection.SocketSettings;
import com.mongodb.connection.SocketStreamFactory;
import com.mongodb.connection.SslSettings;
import com.mongodb.event.ClusterListener;
import com.mongodb.event.ConnectionListener;
import com.mongodb.management.JMXConnectionPoolListener;
import com.mongodb.operation.CommandReadOperation;
import com.mongodb.operation.CommandWriteOperation;
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
import org.bson.BsonArray;
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

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = {"com.mongodb.operation","com.newrelic.agent.security.instrumentation.mongo"})
public class CommandWriteOperationTest {
    private static final MongodStarter mongodStarter = MongodStarter.getDefaultInstance();
    private static MongodExecutable mongodExecutable;
    private static MongodProcess mongodProcess;
    private static MongoClient mongoClient;
    private static Cluster cluster;
    private static int port;
    private static final String dbName = "test";
    private static String host = "localhost";
    private static Decoder<DBObject> decoder;
    @BeforeClass
    public static void startMongo() throws Exception {
        port = Network.getFreeServerPort();
        MongodConfig mongodConfig = ImmutableMongodConfig.builder()
                .version(Version.V3_2_0)
                .net(new Net(port, Network.localhostIsIPv6()))
                .build();

        mongodExecutable = mongodStarter.prepare(mongodConfig);
        mongodProcess = mongodExecutable.start();
        mongoClient = new MongoClient(host, port);
        MongoDatabase database = mongoClient.getDatabase(dbName);
        database.createCollection(dbName);
        MongoCollection mcollection = database.getCollection(dbName);
        Document doc = new Document("name", "MongoDB").append("type", "database").append("count", 1).append("info",
                new Document("x", 203).append("y", 102));
        mcollection.insertOne(doc);

        MongoClientOptions options = MongoClientOptions.builder().build();
        cluster = new DefaultClusterFactory().create(
                ClusterSettings.builder().hosts(Collections.singletonList(new ServerAddress(host, port))).build(),
                ServerSettings.builder().build(),
                ConnectionPoolSettings.builder().build(),
                new SocketStreamFactory(SocketSettings.builder().build(), SslSettings.builder().enabled(false).build(), options.getSocketFactory()),
                new SocketStreamFactory(SocketSettings.builder().build(), SslSettings.builder().build(), options.getSocketFactory()),
                new ArrayList<>(), (ClusterListener)null, new JMXConnectionPoolListener(), (ConnectionListener)null);

        CodecRegistry codecRegistry = CodecRegistries.fromRegistries(
                MongoClient.getDefaultCodecRegistry(),
                CodecRegistries.fromCodecs(new DBPersonCodec())
        );

        decoder = codecRegistry.get(DBObject.class);
    }

    @AfterClass
    public static void stopMongo() {
        if (!cluster.isClosed()){
            cluster.close();
        }
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
        BsonDocument document = new BsonDocument();
        document.put("insert", new BsonString("name"));
        document.put("documents", new BsonArray(Collections.singletonList(new BsonDocument("name", new BsonString("MongoDB")))));

        CommandWriteOperation<DBObject> cmd = new CommandWriteOperation<>("test", document, decoder);
        cmd.execute(new ClusterBinding(cluster, ReadPreference.primary()));

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        NoSQLOperation operation = (NoSQLOperation) operations.get(0);

        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertEquals("No Command Detected", "write", operation.getPayloadType());
        String expected = "[{ \"insert\" : \"name\", \"documents\" : [{ \"name\" : \"MongoDB\" }] }]";
        Assert.assertEquals("No data Found", expected, operation.getPayload().toString());
    }

    @Test
    public void testExecuteAsync(){
        BsonDocument document = new BsonDocument();
        document.put("insert", new BsonString("name"));
        document.put("documents", new BsonArray(Collections.singletonList(new BsonDocument("name", new BsonString("MongoDB")))));


        CommandWriteOperation<DBObject> cmd = new CommandWriteOperation<>("test", document, decoder);

         cmd.executeAsync(new AsyncClusterBinding(cluster, ReadPreference.primary()),(
                 final DBObject doc,final Throwable t)->{
            System.out.println("Execution completed");
        });

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        NoSQLOperation operation = (NoSQLOperation) operations.get(0);

        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertEquals("No Command Detected", "write", operation.getPayloadType());

        String expected = "[{ \"insert\" : \"name\", \"documents\" : [{ \"name\" : \"MongoDB\" }] }]";
        Assert.assertEquals("No data Found", expected, operation.getPayload().toString());
    }
}
