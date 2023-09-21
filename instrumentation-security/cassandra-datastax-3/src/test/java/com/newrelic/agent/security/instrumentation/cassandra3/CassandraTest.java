package com.newrelic.agent.security.instrumentation.cassandra3;

import com.datastax.driver.core.BatchStatement;
import com.datastax.driver.core.BoundStatement;
import com.datastax.driver.core.Cluster;
import com.datastax.driver.core.CodecRegistry;
import com.datastax.driver.core.LocalDate;
import com.datastax.driver.core.Session;
import com.datastax.driver.core.SimpleStatement;
import com.datastax.driver.core.TypeCodec;
import com.datastax.driver.core.querybuilder.Batch;
import com.datastax.driver.core.querybuilder.CassandraUtils;
import com.datastax.driver.core.querybuilder.Delete;
import com.datastax.driver.core.querybuilder.Insert;
import com.datastax.driver.core.querybuilder.QueryBuilder;
import com.datastax.driver.core.querybuilder.Select;
import com.datastax.driver.core.querybuilder.Update;
import com.google.common.collect.ImmutableMap;
import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.api.agent.Trace;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.security.schema.operation.BatchSQLOperation;
import com.newrelic.api.agent.security.schema.operation.SQLOperation;
import com.newrelic.security.test.marker.Java11IncompatibleTest;
import com.newrelic.security.test.marker.Java17IncompatibleTest;
import com.newrelic.security.test.marker.Java9IncompatibleTest;
import org.apache.cassandra.io.util.FileUtils;
import org.cassandraunit.utils.EmbeddedCassandraServerHelper;
import org.joda.time.DateTime;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runner.RunWith;

import java.io.File;
import java.math.BigDecimal;
import java.net.URL;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.UUID;

// Issue when running cassandra unit on Java 9+ - https://github.com/jsevellec/cassandra-unit/issues/249
@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = { "com.datastax.driver.core" })
@Category({ Java9IncompatibleTest.class, Java11IncompatibleTest.class, Java17IncompatibleTest.class })
public class CassandraTest {
    private static Cluster CLUSTER;
    private static Session SESSION;
    private static final List<String> QUERIES = CassandraTestUtils.getQueries();
    private static int PORT;

    @BeforeClass
    public static void beforeClass() throws Exception {
        /* Embedded Cassandra doesn't play nice in java9 - when you attempt to start it, it attempts to create and initialize
        a directory on the local file system. It uses its own FileUtils class do so, which contains a static
        initialization block that tries to cast a ByteBuffer to a DirectBuffer, which doesn't exist in Java 9. This falls
        through to a catch block, which subsequently calls JVMStabilityInspector.inspectThrowable(t), which in turn
        calls DatabaseDescriptor.getDiskFailurePolicy(), and that, in turn, relies on the directory having been created.
        */
        URL config = CassandraTest.class.getResource("/cu-cassandra.yaml");
        System.setProperty("cassandra.config", config.toString());
        EmbeddedCassandraServerHelper.startEmbeddedCassandra();

        PORT = EmbeddedCassandraServerHelper.getNativeTransportPort();
        CLUSTER = Cluster.builder().withPort(PORT).addContactPoint("127.0.0.1").build();

        SESSION = CLUSTER.connect();

        // CREATE A KEYSPACE test and use
        SESSION.execute(QUERIES.get(0));
        SESSION.execute(QUERIES.get(1));

        // create table users and users2
        SESSION.execute(QUERIES.get(2));
        SESSION.execute(QUERIES.get(3));
    }
    @AfterClass
    public static void after() {
        if(SESSION != null){
            SESSION.closeAsync();
        }
        if(CLUSTER != null){
            CLUSTER.closeAsync();
        }
        FileUtils.deleteRecursive(new File("target/"));
    }
    @Test
    public void testStringSimpleStmt() {
        stringSimpleStmt();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        SQLOperation operation = (SQLOperation) operations.get(0);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "executeAsync", operation.getMethodName());
        
        Assert.assertEquals("Invalid Query detected.", QUERIES.get(4), operation.getQuery());
        Assert.assertEquals("Invalid DB-Name.", CassandraUtils.EVENT_CATEGORY, operation.getDbName());
    }
    @Test
    public void testSimpleStmt() {
        simpleStmt();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        SQLOperation operation = (SQLOperation) operations.get(0);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "executeAsync", operation.getMethodName());
        
        Assert.assertEquals("Invalid Query detected.", QUERIES.get(4), operation.getQuery());
        Assert.assertEquals("Invalid DB-Name.", CassandraUtils.EVENT_CATEGORY, operation.getDbName());
    }
    @Test
    public void testSimpleStmtParams() {
        Map<String, String> params = simpleStmtParams();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        SQLOperation operation = (SQLOperation) operations.get(0);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "executeAsync", operation.getMethodName());
        
        Assert.assertEquals("Invalid Query detected.", QUERIES.get(5), operation.getQuery());
        Assert.assertEquals("Invalid DB-Name.", CassandraUtils.EVENT_CATEGORY, operation.getDbName());
        Assert.assertEquals("Wrong params detected", params, operation.getParams());
    }
    @Test
    public void testSimpleStmtNamedParams() {
        Map<String, String> params = simpleStmtNamedParams();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        SQLOperation operation = (SQLOperation) operations.get(0);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "executeAsync", operation.getMethodName());
        
        Assert.assertEquals("Invalid Query detected.", QUERIES.get(6), operation.getQuery());
        Assert.assertEquals("Invalid DB-Name.", CassandraUtils.EVENT_CATEGORY, operation.getDbName());
        Assert.assertEquals("Wrong params detected", params, operation.getParams());
    }
    @Test
    public void testWrappedStmt() {
        wrappedStmt();
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        SQLOperation operation = (SQLOperation) operations.get(0);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "executeAsync", operation.getMethodName());
        
        Assert.assertEquals("Invalid Query detected.", QUERIES.get(4), operation.getQuery());
        Assert.assertEquals("Invalid DB-Name.", CassandraUtils.EVENT_CATEGORY, operation.getDbName());
    }
    @Test
    public void testBoundStmt() {
        Map<String, String> params = boundStmt();
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        SQLOperation operation = (SQLOperation) operations.get(0);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "executeAsync", operation.getMethodName());
        
        Assert.assertEquals("Invalid Query detected.", QUERIES.get(7), operation.getQuery());
        Assert.assertEquals("Invalid DB-Name.", CassandraUtils.EVENT_CATEGORY, operation.getDbName());
        Assert.assertEquals("Wrong params detected", params, operation.getParams());
    }
    @Test
    public void testBuiltStmtInsert() {
        Map<String, String> params = builtStmtInsert();
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        SQLOperation operation = (SQLOperation) operations.get(0);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "executeAsync", operation.getMethodName());
        
        Assert.assertEquals("Invalid Query detected.", QUERIES.get(10), operation.getQuery());
        Assert.assertEquals("Invalid DB-Name.", CassandraUtils.EVENT_CATEGORY, operation.getDbName());
        Assert.assertEquals("Wrong params detected", params, operation.getParams());
    }
    @Test
    public void testBuiltStmtSelect() {
        Map<String, String> params = builtStmtSelect();
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        SQLOperation operation = (SQLOperation) operations.get(0);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "executeAsync", operation.getMethodName());
        
        Assert.assertEquals("Invalid Query detected.", QUERIES.get(12), operation.getQuery());
        Assert.assertEquals("Invalid DB-Name.", CassandraUtils.EVENT_CATEGORY, operation.getDbName());
        Assert.assertEquals("Wrong params detected", params, operation.getParams());
    }
    @Test
    public void testBuiltStmtUpdate() {
        Map<String, String> params = builtStmtUpdate();
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        SQLOperation operation = (SQLOperation) operations.get(0);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "executeAsync", operation.getMethodName());
        
        Assert.assertEquals("Invalid Query detected.", QUERIES.get(14), operation.getQuery());
        Assert.assertEquals("Invalid DB-Name.", CassandraUtils.EVENT_CATEGORY, operation.getDbName());
        Assert.assertEquals("Wrong params detected", params, operation.getParams());
    }
    @Test
    public void testBuiltStmtDelete() {
        Map<String, String> params = builtStmtDelete();
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        SQLOperation operation = (SQLOperation) operations.get(0);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "executeAsync", operation.getMethodName());
        
        Assert.assertEquals("Invalid Query detected.", QUERIES.get(13), operation.getQuery());
        Assert.assertEquals("Invalid DB-Name.", CassandraUtils.EVENT_CATEGORY, operation.getDbName());
        Assert.assertEquals("Wrong params detected", params, operation.getParams());
    }
    @Test
    public void testBuiltStmtBatch() {
        Map<String, String> params = builtStmtBatch();
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        SQLOperation operation = (SQLOperation) operations.get(0);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "executeAsync", operation.getMethodName());
        
        Assert.assertEquals("Invalid Query detected.", QUERIES.get(11), operation.getQuery());
        Assert.assertEquals("Invalid DB-Name.", CassandraUtils.EVENT_CATEGORY, operation.getDbName());
        Assert.assertEquals("Wrong params detected", params, operation.getParams());
    }
    @Test
    public void testBatchStmt() {
        Map<String, String> params = batchStmt();
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        BatchSQLOperation batchOperation = (BatchSQLOperation) operations.get(0);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, batchOperation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "executeAsync", batchOperation.getMethodName());
        Assert.assertEquals("Wrong number of operations detected", 2, batchOperation.getOperations().size());

        Assert.assertEquals("Invalid Query detected.", QUERIES.get(4), batchOperation.getOperations().get(0).getQuery());
        Assert.assertEquals("Invalid Query detected.", QUERIES.get(5), batchOperation.getOperations().get(1).getQuery());

        Assert.assertEquals("Wrong params detected", new HashMap<>(), batchOperation.getOperations().get(0).getParams());
        Assert.assertEquals("Wrong params detected", params, batchOperation.getOperations().get(1).getParams());

        for (SQLOperation operation: batchOperation.getOperations()) {
            Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
            Assert.assertEquals("Invalid executed method name.", "executeAsync", operation.getMethodName());
            
            Assert.assertEquals("Invalid DB-Name.", CassandraUtils.EVENT_CATEGORY, operation.getDbName());
        }
    }
    @Test
    public void testNestedBatchStmt() {
        Map<String, String> params = nestedBatchStmt();
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        BatchSQLOperation batchOperation = (BatchSQLOperation) operations.get(0);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, batchOperation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "executeAsync", batchOperation.getMethodName());

        Assert.assertEquals("Wrong number of operations detected", 2, batchOperation.getOperations().size());
        Assert.assertEquals("Invalid Query detected.", QUERIES.get(4), batchOperation.getOperations().get(0).getQuery());
        Assert.assertEquals("Invalid Query detected.", QUERIES.get(5), batchOperation.getOperations().get(1).getQuery());

        Assert.assertEquals("Wrong params detected", new HashMap<>(), batchOperation.getOperations().get(0).getParams());
        Assert.assertEquals("Wrong params detected", params, batchOperation.getOperations().get(1).getParams());

        for (SQLOperation operation: batchOperation.getOperations()) {
            Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
            Assert.assertEquals("Invalid executed method name.", "executeAsync", operation.getMethodName());
            
            Assert.assertEquals("Invalid DB-Name.", CassandraUtils.EVENT_CATEGORY, operation.getDbName());
        }
    }
    @Test
    public void testBatchStmtWithBuiltStmt() {
        Map<String, String> params = batchStmtWithBuiltStmt();
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        BatchSQLOperation batchOperation = (BatchSQLOperation) operations.get(0);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, batchOperation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "executeAsync", batchOperation.getMethodName());
        Assert.assertEquals("Wrong number of operations detected", batchOperation.getOperations().size(), 2);

        Assert.assertEquals("Invalid Query detected.", QUERIES.get(14), batchOperation.getOperations().get(0).getQuery());
        Assert.assertEquals("Invalid Query detected.", QUERIES.get(10), batchOperation.getOperations().get(1).getQuery());

        for (SQLOperation operation: batchOperation.getOperations()) {
            Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
            Assert.assertEquals("Invalid executed method name.", "executeAsync", operation.getMethodName());
            
            Assert.assertEquals("Invalid DB-Name.", CassandraUtils.EVENT_CATEGORY, operation.getDbName());
            Assert.assertEquals("Wrong params detected", params, operation.getParams());
        }
    }
    @Test
    public void testCustomCodec() {
        Map<String, String> params = customCodecCase();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 1);

        SQLOperation operation = (SQLOperation) operations.get(1);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "executeAsync", operation.getMethodName());
        
        Assert.assertEquals("Invalid Query detected.", QUERIES.get(7), operation.getQuery());
        Assert.assertEquals("Invalid DB-Name.", CassandraUtils.EVENT_CATEGORY, operation.getDbName());
        Assert.assertEquals("Wrong params detected", params, operation.getParams());
    }
    @Test
    public void testCustomCodec1() {
        Map<String, String> params = customCodecCase1();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 2);

        SQLOperation operation = (SQLOperation) operations.get(2);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "executeAsync", operation.getMethodName());
        
        Assert.assertEquals("Invalid Query detected.", QUERIES.get(9), operation.getQuery());
        Assert.assertEquals("Invalid DB-Name.", CassandraUtils.EVENT_CATEGORY, operation.getDbName());
        Assert.assertEquals("Wrong params detected", params, operation.getParams());
    }

    @Trace(dispatcher = true)
    private void stringSimpleStmt() {
        SESSION.execute(QUERIES.get(4));
    }
    @Trace(dispatcher = true)
    private void simpleStmt() {
        SimpleStatement insertStmt = new SimpleStatement(QUERIES.get(4));
        SESSION.execute(insertStmt);
    }
    @Trace(dispatcher = true)
    private Map<String, String> simpleStmtParams() {
        Map<String, String> params = CassandraTestUtils.getValueParams();

        SimpleStatement insertStmt1 = new SimpleStatement(
                QUERIES.get(5),
                Integer.parseInt(params.get("0")),
                params.get("1"));
        SESSION.execute(insertStmt1);
        return params;
    }
    @Trace(dispatcher = true)
    private Map<String, String> simpleStmtNamedParams() {
        Map<String, String> params = CassandraTestUtils.getNamedParams();

        SimpleStatement insertStmt2 = new SimpleStatement(
                QUERIES.get(6),
                ImmutableMap.of("age", Integer.parseInt(params.get("age")), "email", params.get("email")));
        SESSION.execute(insertStmt2);
        return params;
    }

    @Trace(dispatcher = true)
    private void wrappedStmt() {
        SimpleStatement insertStatement = new SimpleStatement(QUERIES.get(4));
        CassandraTestUtils.SimpleStatementWrapper wrappedInsertStmt = new CassandraTestUtils.SimpleStatementWrapper(insertStatement);
        SESSION.execute(wrappedInsertStmt);
    }
    @Trace(dispatcher = true)
    private Map<String, String> boundStmt() {
        Map<String, String> params = CassandraTestUtils.getBoundParams();

        BoundStatement boundStmt = SESSION.prepare(QUERIES.get(7)).bind();
        boundStmt.setUUID(0, UUID.fromString(params.get("0")));
        boundStmt.set("email", params.get("1"), TypeCodec.varchar());
        boundStmt.setString("email", params.get("1"));
        boundStmt.setInt(2, Integer.parseInt(params.get("2")));
        boundStmt.setBool("isMarried", Boolean.parseBoolean(params.get("3")));
        boundStmt.set("age", Integer.parseInt(params.get("2")), TypeCodec.cint());
        boundStmt.setBytes("img", ByteBuffer.wrap("data".getBytes()));
        boundStmt.setDecimal("phone", new BigDecimal(22222222));
        boundStmt.set("phone", new BigDecimal(22222222), BigDecimal.class);
        boundStmt.setDate("dob", LocalDate.fromDaysSinceEpoch(100));
        boundStmt.setString("name", "ishi");
        boundStmt.setList("events", new ArrayList<>());
        boundStmt.setSet("address", new HashSet<>());
        boundStmt.setMap("marks", new HashMap<>());
        SESSION.execute(boundStmt);
        return params;
    }
    @Trace(dispatcher = true)
    private Map<String, String> builtStmtInsert() {
        Map<String, String> params = new HashMap<>();
        params.put("0", "clun5@gmail.com");
        Insert stmt1 = QueryBuilder.insertInto("users")
                .value("age", 35)
                .value("email", params.get("0"));

        SESSION.execute(stmt1);
        return params;
    }
    @Trace(dispatcher = true)
    private Map<String, String> builtStmtSelect() {
        Map<String, String> params = new HashMap<>();
        params.put("0", "clun5@gmail.com");
        Select.Where stmt2 = QueryBuilder.select().all().from("users")
                .where(QueryBuilder.eq("email", params.get("0")));
        stmt2.setForceNoValues(true);

        SESSION.execute(stmt2);
        return params;
    }
    @Trace(dispatcher = true)
    private Map<String, String> builtStmtDelete() {
        Map<String, String> params = new HashMap<>();
        params.put("0", "clun5@gmail.com");
        Delete.Where stmt3= QueryBuilder.delete().all().from("users").
                where(QueryBuilder.eq("email", params.get("0")));
        SESSION.execute(stmt3);
        return params;
    }
    @Trace(dispatcher = true)
    private Map<String, String> builtStmtUpdate() {
        Map<String, String> params = new HashMap<>();
        params.put("0", "clun5@gmail.com");
        Update.Where stmt4= QueryBuilder.update("users")
                .with(QueryBuilder.set("age", 50))
                .where(QueryBuilder.eq("email", params.get("0")));

        SESSION.execute(stmt4);
        return params;
    }
    @Trace(dispatcher = true)
    private Map<String, String> builtStmtBatch() {
        Map<String, String> params = new HashMap<>();
        params.put("0", "clun5@gmail.com");
        params.put("1", "clun5@gmail.com");

        Insert stmt1 = QueryBuilder.insertInto("users")
                .value("email", params.get("0"))
                .value("age", 30);
        Update.Where stmt4= QueryBuilder.update("users")
                .with(QueryBuilder.set("age", 50))
                .where(QueryBuilder.eq("email", params.get("0")));
        Batch stmt5 = QueryBuilder.batch(stmt1).add(stmt4);
        SESSION.execute(stmt5);
        return params;
    }
    @Trace(dispatcher = true)
    private Map<String, String> batchStmt() {
        Map<String, String> params = new HashMap<>();
        params.put("0", "22");
        params.put("1", "test@gmail.com");
        BoundStatement b1 = new BoundStatement(SESSION.prepare(QUERIES.get(5))).bind().setInt(0, 22).setString("email",params.get("1"));
        CassandraTestUtils.SimpleStatementWrapper wrapper = new CassandraTestUtils.SimpleStatementWrapper(b1);
        BatchStatement batchStmt = new BatchStatement().add(new SimpleStatement(QUERIES.get(4))).add(wrapper);
        SESSION.execute(batchStmt);

        return params;
    }
    @Trace(dispatcher = true)
    private Map<String, String> nestedBatchStmt() {
        Map<String, String> params = new HashMap<>();
        params.put("0", "22");
        params.put("1", "test@gmail.com");

        BoundStatement b1 = new BoundStatement(SESSION.prepare(QUERIES.get(5))).bind().setInt(0, 22).setString("email",params.get("1"));
        BatchStatement batchStmt = new BatchStatement().add(new SimpleStatement(QUERIES.get(4))).add(b1);

        BatchStatement batchStmt2 = new BatchStatement().add(batchStmt);
        SESSION.execute(batchStmt2);
        return params;
    }
    @Trace(dispatcher = true)
    private Map<String, String> batchStmtWithBuiltStmt() {
        Map<String, String> params = new HashMap<>();
        params.put("0", "clun5@gmail.com");

        Insert stmt1 = QueryBuilder.insertInto("users")
                .value("age", 35)
                .value("email", params.get("0"));
        Update.Where stmt4= QueryBuilder.update("users")
                .with(QueryBuilder.set("age", 50))
                .where(QueryBuilder.eq("email", params.get("0")));

        BatchStatement batchStmt2 = new BatchStatement().add(stmt4).add(stmt1);
        SESSION.execute(batchStmt2);
        return params;
    }

    @Trace(dispatcher = true)
    private Map<String, String> customCodecCase() {
        try (Cluster newCluster = Cluster.builder().withPort(PORT).addContactPoint("127.0.0.1").withCodecRegistry(new CodecRegistry()).build()) {
            Session newSession = newCluster.connect("test");

            CodecRegistry codecRegistry = newCluster.getConfiguration().getCodecRegistry();
            codecRegistry.register(new CassandraTestUtils.DateTimeCodec());

            Map<String, String> params = CassandraTestUtils.getBoundParams();

            BoundStatement boundStmt = newSession.prepare(QUERIES.get(7)).bind();
            boundStmt.setUUID(0, UUID.fromString(params.get("0")));
            boundStmt.setBool("isMarried", Boolean.parseBoolean(params.get("3")));
            boundStmt.set("email", params.get("1"), TypeCodec.varchar());
            boundStmt.setString("email", params.get("1"));
            boundStmt.setInt(2, Integer.parseInt(params.get("2")));
            boundStmt.set(2, Integer.parseInt(params.get("2")), TypeCodec.cint());
            boundStmt.setBytes("img", ByteBuffer.wrap("data".getBytes()));
            boundStmt.setDecimal("phone", new BigDecimal(22222222));
            boundStmt.set("phone", new BigDecimal(22222222), BigDecimal.class);
            boundStmt.setDate("dob", LocalDate.fromDaysSinceEpoch(100));
            boundStmt.setString("name", "ishi");
            boundStmt.setList("events", new ArrayList<>());
            boundStmt.setSet("address", new HashSet<>());
            boundStmt.setMap("marks", new HashMap<>());
            newSession.execute(boundStmt);

            newSession.closeAsync();
            return params;
        }
    }

    @Trace(dispatcher = true)
    private Map<String, String> customCodecCase1() {
        try (Cluster newCluster = Cluster.builder().withPort(PORT).addContactPoint("127.0.0.1").withCodecRegistry(new CodecRegistry()).build()) {
            CodecRegistry codecRegistry = newCluster.getConfiguration().getCodecRegistry();
            codecRegistry.register(new CassandraTestUtils.DateTimeCodec());

            Session newSession = newCluster.connect("test");
            newSession.execute(QUERIES.get(8));


            Map<String, String> params = CassandraTestUtils.getCustomCodecParams();

            SimpleStatement stmt = new SimpleStatement(QUERIES.get(9), UUID.fromString(params.get("0")), DateTime.parse(params.get("1")));
            newSession.execute(stmt);
            return params;
        }
    }
}
