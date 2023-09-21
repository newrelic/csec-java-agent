package com.newrelic.agent.security.instrumentation.r2dbc;

import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.api.agent.Trace;
import com.newrelic.api.agent.security.instrumentation.helpers.R2dbcHelper;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.security.schema.operation.SQLOperation;
import io.r2dbc.h2.H2ConnectionConfiguration;
import io.r2dbc.h2.H2ConnectionFactory;
import io.r2dbc.spi.Connection;
import io.r2dbc.spi.ConnectionFactory;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RunWith(SecurityInstrumentationTestRunner.class)
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@InstrumentationTestConfig(includePrefixes = "io.r2dbc.spi")
public class H2StatementTest {

    private static Connection connection;
    private static final List<String> QUERIES = new ArrayList<>();

    @BeforeClass
    public static void setup() {
        QUERIES.add("CREATE TABLE IF NOT EXISTS USERS(id int primary key, first_name varchar(255), last_name varchar(255))");
        QUERIES.add("INSERT INTO USERS VALUES(1, 'Max', 'John')");
        QUERIES.add("SELECT * FROM USERS where first_name = $1");
        QUERIES.add("SELECT * FROM USERS where first_name = ?");
        QUERIES.add("SELECT * FROM USERS where first_name = $1 AND last_name = $2");
        QUERIES.add("SELECT * FROM USERS where first_name = ? AND last_name = ?");

        String DB_NAME = "test";
        ConnectionFactory connectionFactory = new H2ConnectionFactory(
                H2ConnectionConfiguration.builder()
                        .inMemory(DB_NAME)
                        .build()
        );
        connection = Mono.from(connectionFactory.create()).block();
        Mono.from(connection.createStatement(QUERIES.get(0)).execute()).block();
    }

    @AfterClass
    public static void teardown() {
        Mono.from(connection.close()).block();
    }

    @Test
    public void testExecute() {
        execute();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertNotNull("No operations detected", operations);

        SQLOperation operation = (SQLOperation) operations.get(0);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.SQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid method-Name.", R2dbcHelper.METHOD_EXECUTE, operation.getMethodName());
        Assert.assertEquals("Invalid executed parameters.", QUERIES.get(1), operation.getQuery());
    }

    @Test
    public void testBindInt() {
        Map<String, String> params =  bindInt();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertNotNull("No operations detected", operations);

        SQLOperation operation = (SQLOperation) operations.get(0);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.SQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid method-Name.", R2dbcHelper.METHOD_EXECUTE, operation.getMethodName());
        Assert.assertEquals("Invalid executed parameters.", QUERIES.get(3), operation.getQuery());
        Assert.assertNotNull("No params detected", operation.getParams());
        Assert.assertEquals("Invalid Params", params, operation.getParams());
    }

    @Test
    public void testBindInt1() {
        Map<String, String> params = bindInt1();
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertNotNull("No operations detected", operations);

        SQLOperation operation = (SQLOperation) operations.get(0);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.SQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid method-Name.", R2dbcHelper.METHOD_EXECUTE, operation.getMethodName());
        Assert.assertEquals("Invalid executed parameters.", QUERIES.get(5), operation.getQuery());
        Assert.assertNotNull("No params detected", operation.getParams());
        Assert.assertEquals("Invalid Params", params, operation.getParams());
    }

    @Test
    public void testBindString() {
        Map<String, String> params = bindString();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertNotNull("No operations detected", operations);

        SQLOperation operation = (SQLOperation) operations.get(0);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.SQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid method-Name.", R2dbcHelper.METHOD_EXECUTE, operation.getMethodName());
        Assert.assertEquals("Invalid executed parameters.", QUERIES.get(2), operation.getQuery());
        Assert.assertNotNull("No params detected", operation.getParams());
        Assert.assertEquals("Invalid Params", params, operation.getParams());
    }

    @Test
    public void testBindString1() {
        Map<String, String> params = bindString1();
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertNotNull("No operations detected", operations);

        SQLOperation operation = (SQLOperation) operations.get(0);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.SQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid method-Name.", R2dbcHelper.METHOD_EXECUTE, operation.getMethodName());
        Assert.assertEquals("Invalid executed parameters.", QUERIES.get(4), operation.getQuery());
        Assert.assertNotNull("No params detected", operation.getParams());
        Assert.assertEquals("Invalid Params", params, operation.getParams());
    }

    @Test
    public void testBindNullInt() {
        Map<String, String> params = bindNullInt();
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertNotNull("No operations detected", operations);

        SQLOperation operation = (SQLOperation) operations.get(0);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.SQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid method-Name.", R2dbcHelper.METHOD_EXECUTE, operation.getMethodName());
        Assert.assertEquals("Invalid executed parameters.", QUERIES.get(3), operation.getQuery());
        Assert.assertNotNull("No params detected", operation.getParams());
        Assert.assertEquals("Invalid Params", params, operation.getParams());
    }

    @Test
    public void testBindNullInt1() {
        Map<String, String> params = bindNullInt1();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertNotNull("No operations detected", operations);

        SQLOperation operation = (SQLOperation) operations.get(0);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.SQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid method-Name.", R2dbcHelper.METHOD_EXECUTE, operation.getMethodName());
        Assert.assertEquals("Invalid executed parameters.", QUERIES.get(5), operation.getQuery());
        Assert.assertNotNull("No params detected", operation.getParams());
        Assert.assertEquals("Invalid Params", params, operation.getParams());
    }

    @Test
    public void testBindNullString() {
        Map<String, String> params = bindNullString();
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertNotNull("No operations detected", operations);

        SQLOperation operation = (SQLOperation) operations.get(0);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.SQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid method-Name.", R2dbcHelper.METHOD_EXECUTE, operation.getMethodName());
        Assert.assertEquals("Invalid executed parameters.", QUERIES.get(2), operation.getQuery());
        Assert.assertNotNull("No params detected", operation.getParams());
        Assert.assertEquals("Invalid Params", params, operation.getParams());
    }

    @Test
    public void testBindNullString1() {
        Map<String, String> params =  bindNullString1();
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertNotNull("No operations detected", operations);

        SQLOperation operation = (SQLOperation) operations.get(0);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.SQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid method-Name.", R2dbcHelper.METHOD_EXECUTE, operation.getMethodName());
        Assert.assertEquals("Invalid executed parameters.", QUERIES.get(4), operation.getQuery());
        Assert.assertNotNull("No params detected", operation.getParams());
        Assert.assertEquals("Invalid Params", params, operation.getParams());
    }

    @Trace(dispatcher = true)
    private void execute(){
        Mono.from(connection.createStatement(QUERIES.get(1)).execute()).block();
    }

    @Trace(dispatcher = true)
    private Map<String, String> bindInt(){
        Mono.from(connection.createStatement(QUERIES.get(3))
                .bind(0, "Max")
                .execute()).block();

        Map<String, String> params =new HashMap<>();
        params.put("0","Max");
        return params;
    }

    @Trace(dispatcher = true)
    private Map<String, String> bindInt1(){
        Mono.from(connection.createStatement(QUERIES.get(5))
                .bind(0, "Max")
                .bind(1,"John")
                .execute()).block();

        Map<String, String> params =new HashMap<>();
        params.put("0","Max");
        params.put("1","John");
        return params;
    }

    @Trace(dispatcher = true)
    private Map<String, String> bindString(){
        Mono.from(connection.createStatement(QUERIES.get(2))
                .bind("$1", "Max")
                .execute()).block();

        Map<String, String> params =new HashMap<>();
        params.put("$1","Max");
        return params;
    }

    @Trace(dispatcher = true)
    private Map<String, String> bindString1(){
        Mono.from(connection.createStatement(QUERIES.get(4))
                .bind("$1", "Max")
                .bind("$2", "John")
                .execute()).block();

        Map<String, String> params =new HashMap<>();
        params.put("$1","Max");
        params.put("$2","John");
        return params;
    }

    @Trace(dispatcher = true)
    private Map<String, String> bindNullInt(){
        Mono.from(connection.createStatement(QUERIES.get(3))
                .bindNull(0, String.class)
                .execute()).block();

        Map<String, String> params =new HashMap<>();
        params.put("0","class java.lang.String");
        return params;
    }

    @Trace(dispatcher = true)
    private Map<String, String> bindNullInt1(){
        Mono.from(connection.createStatement(QUERIES.get(5))
                .bindNull(0, String.class)
                .bindNull(1, String.class)
                .execute()).block();

        Map<String, String> params =new HashMap<>();
        params.put("0","class java.lang.String");
        params.put("1","class java.lang.String");
        return params;
    }

    @Trace(dispatcher = true)
    private Map<String, String> bindNullString(){
        Mono.from(connection.createStatement(QUERIES.get(2))
                .bindNull("$1", String.class)
                .execute()).block();

        Map<String, String> params =new HashMap<>();
        params.put("$1","class java.lang.String");
        return params;
    }

    @Trace(dispatcher = true)
    private Map<String, String> bindNullString1(){
        Mono.from(connection.createStatement(QUERIES.get(4))
                .bindNull("$1", String.class)
                .bindNull("$2", String.class)
                .execute()).block();

        Map<String, String> params =new HashMap<>();
        params.put("$1","class java.lang.String");
        params.put("$2","class java.lang.String");
        return params;
    }
}