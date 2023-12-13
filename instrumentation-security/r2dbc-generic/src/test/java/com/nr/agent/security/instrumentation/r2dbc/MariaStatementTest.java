package com.nr.agent.security.instrumentation.r2dbc;

import ch.vorburger.exec.ManagedProcessException;
import ch.vorburger.mariadb4j.DB;
import ch.vorburger.mariadb4j.DBConfigurationBuilder;
import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.api.agent.Trace;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.security.schema.operation.SQLOperation;
import io.r2dbc.spi.Connection;
import io.r2dbc.spi.ConnectionFactories;
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
public class MariaStatementTest {

    public static DBConfigurationBuilder builder;
    public static DB mariaDb;
    public static Connection connection;
    private static final String DB_USER = "user";
    private static final String DB_PASSWORD = "password";
    private static final String HOST = "localhost";
    private static final List<String> QUERIES = new ArrayList<>();
    private static final String DB_NAME = "test";

    @BeforeClass
    public static void setup() throws Exception {
        QUERIES.add("CREATE TABLE IF NOT EXISTS USERS(id int primary key, first_name varchar(255), last_name varchar(255))");
        QUERIES.add("INSERT INTO USERS VALUES(1, 'Max', 'John')");
        QUERIES.add("INSERT INTO USERS VALUES(2, :first_name, 'John')");
        QUERIES.add("SELECT * FROM USERS where first_name = ?");
        QUERIES.add("SELECT * FROM USERS where first_name = :first_name AND last_name = :last_name");
        QUERIES.add("SELECT * FROM USERS where first_name = ? AND last_name = ?");

        builder = DBConfigurationBuilder.newBuilder().setPort(0);
        mariaDb = DB.newEmbeddedDB(builder.build());
        mariaDb.start();
        mariaDb.createDB(DB_NAME);
        mariaDb.source("users.sql", DB_USER, DB_PASSWORD, DB_NAME);

        String url = builder.getURL(DB_NAME)
                .replace("mysql", "mariadb")
                .replace("jdbc", "r2dbc")
                .replace(HOST, "user:password@localhost");

        ConnectionFactory connectionFactory = ConnectionFactories.get(url);
        connection = Mono.from(connectionFactory.create()).block();
        Mono.from(connection.createStatement(QUERIES.get(0)).execute()).block();
    }

    @AfterClass
    public static void teardown() throws ManagedProcessException {
        Mono.from(connection.close()).block();
        mariaDb.stop();
    }

    @Test
    public void testExecute() {
        execute();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertNotNull("No operations detected", operations);

        SQLOperation operation = (SQLOperation) operations.get(0);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.SQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid method-Name.", "execute", operation.getMethodName());
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
        Assert.assertEquals("Invalid method-Name.", "execute", operation.getMethodName());
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
        Assert.assertEquals("Invalid method-Name.", "execute", operation.getMethodName());
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
        Assert.assertEquals("Invalid method-Name.", "execute", operation.getMethodName());
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
        Assert.assertEquals("Invalid method-Name.", "execute", operation.getMethodName());
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
        Assert.assertEquals("Invalid method-Name.", "execute", operation.getMethodName());
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
        Assert.assertEquals("Invalid method-Name.", "execute", operation.getMethodName());
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
        Assert.assertEquals("Invalid method-Name.", "execute", operation.getMethodName());
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
        Assert.assertEquals("Invalid method-Name.", "execute", operation.getMethodName());
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
                .bind("first_name", "Max")
                .execute()).block();

        Map<String, String> params =new HashMap<>();
        params.put("first_name","Max");
        return params;
    }

    @Trace(dispatcher = true)
    private Map<String, String> bindString1(){
        Mono.from(connection.createStatement(QUERIES.get(4))
                .bind("first_name", "Max")
                .bind("last_name", "John")
                .execute()).block();

        Map<String, String> params =new HashMap<>();
        params.put("first_name","Max");
        params.put("last_name","John");
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
                .bindNull("first_name", String.class)
                .execute()).block();

        Map<String, String> params =new HashMap<>();
        params.put("first_name","class java.lang.String");
        return params;
    }

    @Trace(dispatcher = true)
    private Map<String, String> bindNullString1(){
        Mono.from(connection.createStatement(QUERIES.get(4))
                .bindNull("first_name", String.class)
                .bindNull("last_name", String.class)
                .execute()).block();

        Map<String, String> params =new HashMap<>();
        params.put("first_name","class java.lang.String");
        params.put("last_name","class java.lang.String");
        return params;
    }
}