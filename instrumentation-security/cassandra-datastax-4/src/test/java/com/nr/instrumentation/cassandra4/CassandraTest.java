package com.nr.instrumentation.cassandra4;

import com.datastax.oss.driver.api.core.cql.BatchStatement;
import com.datastax.oss.driver.api.core.cql.BatchType;
import com.datastax.oss.driver.api.core.cql.SimpleStatement;
import com.datastax.oss.driver.api.querybuilder.QueryBuilder;
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
import com.nr.instrumentation.security.cassandra4.CassandraUtils;
import org.apache.cassandra.io.util.FileUtils;
import org.cassandraunit.CassandraCQLUnit;
import org.cassandraunit.dataset.cql.ClassPathCQLDataSet;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runner.RunWith;

import java.io.File;
import java.math.BigDecimal;
import java.nio.ByteBuffer;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.UUID;

// Issue when running cassandra unit on Java 9+ - https://github.com/jsevellec/cassandra-unit/issues/249
@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = { "com.datastax", "com.nr.instrumentation" })
@Category({ Java9IncompatibleTest.class, Java11IncompatibleTest.class, Java17IncompatibleTest.class })
public class CassandraTest {
    @ClassRule
    public static CassandraCQLUnit CASSANDRA = new CassandraCQLUnit(new ClassPathCQLDataSet("users.cql", "test"));
    private static final List<String> QUERIES = CassandraTestUtils.getQueries();
    @AfterClass
    public static void after() {
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
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        
        Assert.assertEquals("Invalid Query detected.", QUERIES.get(0), operation.getQuery());
        Assert.assertEquals("Invalid DB-Name.", CassandraUtils.EVENT_CATEGORY, operation.getDbName());
    }
    @Test
    public void testSimpleStmtPositionalValues() {
        simpleStmtPositionalValues();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        SQLOperation operation = (SQLOperation) operations.get(0);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        
        Assert.assertEquals("Invalid Query detected.", QUERIES.get(1), operation.getQuery());
        Assert.assertEquals("Invalid DB-Name.", CassandraUtils.EVENT_CATEGORY, operation.getDbName());
    }
    @Test
    public void testSimpleStmtNamedValues() {
        Map<String, String> params = simpleStmtNamedValues();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        SQLOperation operation = (SQLOperation) operations.get(0);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        
        Assert.assertEquals("Invalid Query detected.", QUERIES.get(2), operation.getQuery());
        Assert.assertEquals("Invalid DB-Name.", CassandraUtils.EVENT_CATEGORY, operation.getDbName());
        Assert.assertEquals("Wrong params detected", params, operation.getParams());
    }

    @Test
    public void testQueryBuilder() {
        queryBuilder();
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        SQLOperation operation = (SQLOperation) operations.get(0);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        
        Assert.assertEquals("Invalid Query detected.", QUERIES.get(6), operation.getQuery());
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
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        
        Assert.assertEquals("Invalid Query detected.", QUERIES.get(3), operation.getQuery());
        Assert.assertEquals("Invalid DB-Name.", CassandraUtils.EVENT_CATEGORY, operation.getDbName());
        Assert.assertEquals("Wrong params detected", params, operation.getParams());
    }
    @Test
    public void testQueryBuilderPositionalValues() {
        Map<String, String> params = queryBuilderPositionalValues();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        SQLOperation operation = (SQLOperation) operations.get(0);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        
        Assert.assertEquals("Invalid Query detected.", QUERIES.get(4), operation.getQuery());
        Assert.assertEquals("Invalid DB-Name.", CassandraUtils.EVENT_CATEGORY, operation.getDbName());
        Assert.assertEquals("Wrong params detected", params, operation.getParams());
    }

    @Test
    public void testQueryBuilderNamedValues() {
        Map<String, String> params = queryBuilderNamedValues();
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        SQLOperation operation = (SQLOperation) operations.get(0);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        
        Assert.assertEquals("Invalid Query detected.", QUERIES.get(5), operation.getQuery());
        Assert.assertEquals("Invalid DB-Name.", CassandraUtils.EVENT_CATEGORY, operation.getDbName());
        Assert.assertEquals("Wrong params detected", params, operation.getParams());
    }
    @Test
    public void testQueryBuilderInsertPositionalParams() {
        Map<String, String> params = queryBuilderInsertPositionalParams();
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        SQLOperation operation = (SQLOperation) operations.get(0);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        
        Assert.assertEquals("Invalid Query detected.", QUERIES.get(1), operation.getQuery());
        Assert.assertEquals("Invalid DB-Name.", CassandraUtils.EVENT_CATEGORY, operation.getDbName());
        Assert.assertEquals("Wrong params detected", params, operation.getParams());
    }
    @Test
    public void testQueryBuilderInsertNamedParams() {
        Map<String, String> params = queryBuilderInsertNamedParams();
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        SQLOperation operation = (SQLOperation) operations.get(0);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        
        Assert.assertEquals("Invalid Query detected.", QUERIES.get(2), operation.getQuery());
        Assert.assertEquals("Invalid DB-Name.", CassandraUtils.EVENT_CATEGORY, operation.getDbName());
        Assert.assertEquals("Wrong params detected", params, operation.getParams());
    }
    @Test
    public void testQueryBuilderUpdatePositionalParams() {
        Map<String, String> params = queryBuilderUpdatePositionalParams();
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        SQLOperation operation = (SQLOperation) operations.get(0);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        
        Assert.assertEquals("Invalid Query detected.", QUERIES.get(9), operation.getQuery());
        Assert.assertEquals("Invalid DB-Name.", CassandraUtils.EVENT_CATEGORY, operation.getDbName());
        Assert.assertEquals("Wrong params detected", params, operation.getParams());
    }
    @Test
    public void testQqueryBuilderUpdateNamedParams() {
        Map<String, String> params = queryBuilderUpdateNamedParams();
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        SQLOperation operation = (SQLOperation) operations.get(0);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        
        Assert.assertEquals("Invalid Query detected.", QUERIES.get(10), operation.getQuery());
        Assert.assertEquals("Invalid DB-Name.", CassandraUtils.EVENT_CATEGORY, operation.getDbName());
        Assert.assertEquals("Wrong params detected", params, operation.getParams());
    }
    @Test
    public void testQueryBuilderDeletePositionalParams() {
        Map<String, String> params = queryBuilderDeletePositionalParams();
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        SQLOperation operation = (SQLOperation) operations.get(0);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        
        Assert.assertEquals("Invalid Query detected.", QUERIES.get(7), operation.getQuery());
        Assert.assertEquals("Invalid DB-Name.", CassandraUtils.EVENT_CATEGORY, operation.getDbName());
        Assert.assertEquals("Wrong params detected", params, operation.getParams());
    }
    @Test
    public void testQueryBuilderDeleteNamedParams() {
        Map<String, String> params = queryBuilderDeleteNamedParams();
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        SQLOperation operation = (SQLOperation) operations.get(0);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        
        Assert.assertEquals("Invalid Query detected.", QUERIES.get(8), operation.getQuery());
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
        Assert.assertEquals("Invalid executed method name.", "execute", batchOperation.getMethodName());
        Assert.assertEquals("Wrong number of operations detected", 3, batchOperation.getOperations().size());

        Assert.assertEquals("Invalid Query detected.", QUERIES.get(7), batchOperation.getOperations().get(0).getQuery());
        Assert.assertEquals("Invalid Query detected.", QUERIES.get(1), batchOperation.getOperations().get(1).getQuery());
        Assert.assertEquals("Invalid Query detected.", QUERIES.get(9), batchOperation.getOperations().get(2).getQuery());

        Assert.assertEquals("Wrong params detected", CassandraTestUtils.getValueParams(), batchOperation.getOperations().get(0).getParams());
        Assert.assertEquals("Wrong params detected", params, batchOperation.getOperations().get(2).getParams());
        params = CassandraTestUtils.getValueParams();
        params.put("1","35");
        Assert.assertEquals("Wrong params detected", params, batchOperation.getOperations().get(1).getParams());

        for (SQLOperation operation: batchOperation.getOperations()) {
            Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
            Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
            
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
        Assert.assertEquals("Invalid executed method name.", "execute", batchOperation.getMethodName());

        Assert.assertEquals("Wrong number of operations detected", 3, batchOperation.getOperations().size());
        Assert.assertEquals("Invalid Query detected.", QUERIES.get(7), batchOperation.getOperations().get(0).getQuery());
        Assert.assertEquals("Invalid Query detected.", QUERIES.get(1), batchOperation.getOperations().get(1).getQuery());
        Assert.assertEquals("Invalid Query detected.", QUERIES.get(9), batchOperation.getOperations().get(2).getQuery());

        Assert.assertEquals("Wrong params detected", CassandraTestUtils.getValueParams(), batchOperation.getOperations().get(0).getParams());
        Assert.assertEquals("Wrong params detected", params, batchOperation.getOperations().get(2).getParams());
        params = CassandraTestUtils.getValueParams();
        params.put("1","35");
        Assert.assertEquals("Wrong params detected", params, batchOperation.getOperations().get(1).getParams());

        for (SQLOperation operation: batchOperation.getOperations()) {
            Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.NOSQL_DB_COMMAND, operation.getCaseType());
            Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
            Assert.assertEquals("Invalid DB-Name.", CassandraUtils.EVENT_CATEGORY, operation.getDbName());
        }
    }

    @Trace(dispatcher = true)
    private void stringSimpleStmt() {
        CASSANDRA.getSession().execute(QUERIES.get(0));
    }
    @Trace(dispatcher = true)
    private void simpleStmtPositionalValues() {
        ArrayList<Object> positionalValue = new ArrayList<>();
        positionalValue.add("test@gmail.com");
        positionalValue.add(2);
        CASSANDRA.getSession().execute(SimpleStatement.newInstance(QUERIES.get(1)).setPositionalValues(positionalValue));
    }
    @Trace(dispatcher = true)
    private Map<String, String> simpleStmtNamedValues() {
        Map<String, String> namedValues = CassandraTestUtils.getNamedParams();
        namedValues.put("age", "35");

        Map<String, Object> params = new HashMap<>();
        params.put("age", 35);
        params.put("email", "bob1@example.com");

        CASSANDRA.getSession().execute(SimpleStatement.newInstance(QUERIES.get(2)).setNamedValues(params));
        return namedValues;
    }
    @Trace(dispatcher = true)
    private void queryBuilder() {
        CASSANDRA.getSession().execute(QueryBuilder.selectFrom("users").all().build());
    }

    @Trace(dispatcher = true)
    private Map<String, String> queryBuilderPositionalValues() {
        ArrayList<Object> positionalValue = new ArrayList<>();
        positionalValue.add("bob1@example.com");
        CASSANDRA.getSession().executeAsync(
            QueryBuilder.selectFrom("users").all()
                .whereColumn("email")
                .isEqualTo(QueryBuilder.bindMarker())
                .build()
                .setPositionalValues(positionalValue)
        );
        return CassandraTestUtils.getValueParams();
    }
    @Trace(dispatcher = true)
    private Map<String, String> queryBuilderNamedValues() {
        Map<String, Object> params = new HashMap<>();
        params.put("email", "bob1@example.com");
        CASSANDRA.getSession().execute(
            QueryBuilder.selectFrom("users").all()
                .whereColumn("email")
                .isEqualTo(QueryBuilder.bindMarker("email"))
                .build()
                .setNamedValues(params)
        );
        return CassandraTestUtils.getNamedParams();
    }
    @Trace(dispatcher = true)
    private Map<String, String> boundStmt() {
        Map<String, String> params = CassandraTestUtils.getBoundParams();

        CASSANDRA.getSession().prepare(SimpleStatement.builder(QUERIES.get(3))
            .addPositionalValue(UUID.fromString(params.get("0")))
            .addPositionalValue(params.get("1"))
            .addPositionalValue(Integer.parseInt(params.get("2")))
            .addPositionalValue(Boolean.parseBoolean(params.get("3")))
            .addPositionalValue(ByteBuffer.wrap("data".getBytes()))
            .addPositionalValue(new BigDecimal(22222222))
            .addPositionalValue(LocalDate.of(2000,1,1))
            .addPositionalValue("ishi")
            .addPositionalValue(new ArrayList<>())
            .addPositionalValue(new HashSet<>())
            .addPositionalValue(new HashMap<>())
            .build()).bind();
        return params;
    }
    @Trace(dispatcher = true)
    private Map<String, String> queryBuilderInsertPositionalParams() {
        ArrayList<Object> obj = new ArrayList<>();
        obj.add("bob1@example.com");
        obj.add(35);

        Map<String, String> positionalValues = new HashMap<>();
        positionalValues.put("0", "bob1@example.com");
        positionalValues.put("1", "35");

        SimpleStatement query = QueryBuilder
                .insertInto("users")
                .value("email", QueryBuilder.bindMarker())
                .value("age", QueryBuilder.bindMarker())
                .build().setPositionalValues(obj);
        CASSANDRA.session.execute(query);
        return positionalValues;
    }
    @Trace(dispatcher = true)
    private Map<String, String> queryBuilderInsertNamedParams() {
        Map<String, Object> obj = new HashMap<>();
        obj.put("email", "bob1@example.com");
        obj.put("age", 35);

        Map<String, String> namedValues = CassandraTestUtils.getNamedParams();
        namedValues.put("age", "35");

        SimpleStatement query = QueryBuilder
                .insertInto("users")
                .value("email", QueryBuilder.bindMarker("email"))
                .value("age", QueryBuilder.bindMarker("age"))
                .build().setNamedValues(obj);
        CASSANDRA.session.executeAsync(query);
        return namedValues;
    }
    @Trace(dispatcher = true)
    private Map<String, String> queryBuilderUpdatePositionalParams() {
        ArrayList<Object> obj = new ArrayList<>();
        obj.add(35);
        obj.add("bob1@example.com");

        Map<String, String> params = new HashMap<>();
        params.put("0", "35");
        params.put("1", "bob1@example.com");

        SimpleStatement query = QueryBuilder
                .update("users")
                .setColumn("age", QueryBuilder.bindMarker())
                .whereColumn("email").isEqualTo(QueryBuilder.bindMarker())
                .build().setPositionalValues(obj);

        CASSANDRA.session.executeAsync(query);
        return params;
    }
    @Trace(dispatcher = true)
    private Map<String, String> queryBuilderUpdateNamedParams() {
        Map<String, Object> obj = new HashMap<>();
        obj.put("email", "bob1@example.com");
        obj.put("age", 35);

        Map<String, String> namedValues = CassandraTestUtils.getNamedParams();
        namedValues.put("age", "35");

        SimpleStatement query = QueryBuilder
                .update("users")
                .setColumn("age", QueryBuilder.bindMarker("age"))
                .whereColumn("email").isEqualTo(QueryBuilder.bindMarker("email"))
                .build().setNamedValues(obj);
        CASSANDRA.session.execute(query);
        return namedValues;
    }
    @Trace(dispatcher = true)
    private Map<String, String> queryBuilderDeletePositionalParams() {
        Map<String, String> params = new HashMap<>();
        params.put("0", "test@gmail.com");

        ArrayList<Object> obj = new ArrayList<>();
        obj.add("test@gmail.com");

        SimpleStatement query = QueryBuilder
                .deleteFrom("users")
                .whereColumn("email").isEqualTo(QueryBuilder.bindMarker())
                .build().setPositionalValues(obj);
        CASSANDRA.session.execute(query);
        return params;
    }
    @Trace(dispatcher = true)
    private Map<String, String> queryBuilderDeleteNamedParams() {
        Map<String, String> params = new HashMap<>();
        params.put("email", "test@gmail.com");

        Map<String, Object> obj = new HashMap<>();
        obj.put("email", "test@gmail.com");

        SimpleStatement query = QueryBuilder
                .deleteFrom("users")
                .whereColumn("email").isEqualTo(QueryBuilder.bindMarker("email"))
                .build().setNamedValues(obj);
        CASSANDRA.session.executeAsync(query);
        return params;
    }
    @Trace(dispatcher = true)
    private Map<String, String> batchStmt() {
        Map<String, String> params = new HashMap<>();
        params.put("0", "35");
        params.put("1", "bob1@example.com");

        ArrayList<Object> obj = new ArrayList<>();
        obj.add("bob1@example.com");
        obj.add(35);

        ArrayList<Object> obj1 = new ArrayList<>();
        obj1.add(35);
        obj1.add("bob1@example.com");

        BatchStatement batchStmt = BatchStatement.builder(BatchType.UNLOGGED)
                .addStatement(SimpleStatement.builder(QUERIES.get(7)).addPositionalValue("bob1@example.com").build())
                .addStatement(SimpleStatement.builder(QUERIES.get(1)).addPositionalValues(obj).build())
                .addStatement(SimpleStatement.builder(QUERIES.get(9)).addPositionalValues(obj1).build()).build();

        CASSANDRA.getSession().execute(batchStmt);
        return params;
    }
    @Trace(dispatcher = true)
    private Map<String, String> nestedBatchStmt() {
        Map<String, String> params = new HashMap<>();
        params.put("1", "bob1@example.com");
        params.put("0", "35");

        ArrayList<Object> obj = new ArrayList<>();
        obj.add("bob1@example.com");
        obj.add(35);

        ArrayList<Object> obj1 = new ArrayList<>();
        obj1.add(35);
        obj1.add("bob1@example.com");

        BatchStatement batchStmt = BatchStatement.builder(BatchType.UNLOGGED)
                .addStatement(SimpleStatement.builder(QUERIES.get(7)).addPositionalValue("bob1@example.com").build())
                .addStatement(SimpleStatement.builder(QUERIES.get(1)).addPositionalValues(obj).build())
                .addStatement(SimpleStatement.builder(QUERIES.get(9)).addPositionalValues(obj1).build()).build();

        BatchStatement batchStmt1 = BatchStatement.builder(BatchType.UNLOGGED).addStatements(batchStmt).build();
        CASSANDRA.getSession().execute(batchStmt1);
        return params;
    }
}
