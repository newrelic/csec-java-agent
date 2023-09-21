package com.newrelic.agent.security.instrumentation.r2dbc;

import ch.vorburger.exec.ManagedProcessException;
import ch.vorburger.mariadb4j.DB;
import ch.vorburger.mariadb4j.DBConfigurationBuilder;
import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.api.agent.Trace;
import com.newrelic.api.agent.security.instrumentation.helpers.R2dbcHelper;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.security.schema.operation.SQLOperation;
import io.r2dbc.spi.Connection;
import io.r2dbc.spi.ConnectionFactories;
import io.r2dbc.spi.ConnectionFactory;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.List;

@RunWith(SecurityInstrumentationTestRunner.class)
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@InstrumentationTestConfig(includePrefixes = "io.r2dbc.spi")
public class MySQLTest {
    public static DBConfigurationBuilder builder;
    public static DB mariaDb;
    public static Connection connection;
    private static final String DB_USER = "user";
    private static final String DB_PASSWORD = "password";
    private static final String HOST = "localhost";
    private static final List<String> QUERIES = new ArrayList<>();
    private static final String DB_NAME = "test";
    private static String DB_CONNECTION;

    @BeforeClass
    public static void setup() throws ManagedProcessException {
        QUERIES.add("CREATE TABLE IF NOT EXISTS USERS(id int primary key, first_name varchar(255), last_name varchar(255))");
        QUERIES.add("INSERT INTO USERS(id, first_name, last_name) VALUES(1, 'Max', 'Power')");
        QUERIES.add("SELECT * FROM USERS");

        builder = DBConfigurationBuilder.newBuilder().setPort(0);
        mariaDb = DB.newEmbeddedDB(builder.build());
        mariaDb.start();
        mariaDb.createDB(DB_NAME);
        mariaDb.source("users.sql", DB_USER, DB_PASSWORD, DB_NAME);

        DB_CONNECTION = builder.getURL(DB_NAME)
                .replace("jdbc", "r2dbc")
                .replace(HOST, "user:password@localhost");
    }

    @AfterClass
    public static void stop() throws Exception {
        mariaDb.stop();
    }
    @After
    public void teardown() {
        Mono.from(connection.close()).block();
    }

    @Test
    public void testCreateStatement() {
        connection();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertNotNull("No operations detected", operations);

        SQLOperation operation = (SQLOperation) operations.get(0);
        Assert.assertEquals("Wrong event category.", VulnerabilityCaseType.SQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Wrong method-Name.", R2dbcHelper.METHOD_EXECUTE, operation.getMethodName());
        Assert.assertEquals("Wrong executed parameters.", QUERIES.get(0), operation.getQuery());
    }

    @Test
    public void testCreateStatement1() {
        connection1();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertNotNull("No operations detected", operations);

        SQLOperation operation = (SQLOperation) operations.get(0);
        Assert.assertEquals("Wrong event category.", VulnerabilityCaseType.SQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Wrong method-Name.", R2dbcHelper.METHOD_EXECUTE, operation.getMethodName());
        Assert.assertEquals("Wrong executed parameters.", QUERIES.get(0), operation.getQuery());
    }

    @Test
    public void testCreateStatement2() {
        connection2();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertNotNull("No operations detected", operations);

        SQLOperation operation = (SQLOperation) operations.get(0);
        Assert.assertEquals("Wrong event category.", VulnerabilityCaseType.SQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Wrong method-Name.", R2dbcHelper.METHOD_EXECUTE, operation.getMethodName());
        Assert.assertEquals("Wrong executed parameters.", QUERIES.get(0), operation.getQuery());
    }

    @Test
    public void testCreateStatement3() {
        connection3();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertNotNull("No operations detected", operations);

        SQLOperation operation = (SQLOperation) operations.get(0);
        Assert.assertEquals("Wrong event category.", VulnerabilityCaseType.SQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Wrong method-Name.", R2dbcHelper.METHOD_EXECUTE, operation.getMethodName());
        Assert.assertEquals("Wrong executed parameters.", QUERIES.get(0), operation.getQuery());
    }


    @Test
    public void testCreateBatch() {
        connection4();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertNotNull("No operations detected", operations);

        SQLOperation operation = (SQLOperation) operations.get(0);
        Assert.assertEquals("Wrong event category.", VulnerabilityCaseType.SQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Wrong method-Name.", R2dbcHelper.METHOD_EXECUTE, operation.getMethodName());
        Assert.assertEquals("Wrong executed parameters.", QUERIES.get(0), operation.getQuery());
    }
    @Test
    public void testCreateBatch5() {
        connection5();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertNotNull("No operations detected", operations);

        SQLOperation operation = (SQLOperation) operations.get(0);
        Assert.assertEquals("Wrong event category.", VulnerabilityCaseType.SQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Wrong method-Name.", R2dbcHelper.METHOD_EXECUTE, operation.getMethodName());
        Assert.assertEquals("Wrong executed parameters.", QUERIES.get(0), operation.getQuery());
    }


    @Trace(dispatcher = true)
    private void connection() {
        ConnectionFactory connectionFactory = ConnectionFactories.get(DB_CONNECTION);
        connection = Mono.from(connectionFactory.create()).block();
        Mono.from(connection.createStatement(QUERIES.get(0)).execute()).block();
    }


    @Trace(dispatcher = true)
    private void connection1() {
        ConnectionFactory connectionFactory = ConnectionFactories.get(DB_CONNECTION);
        connection = Mono.from(connectionFactory.create()).block();
        Flux.from(connection.createStatement(QUERIES.get(0)).execute()).blockFirst();
    }

    @Trace(dispatcher = true)
    private void connection2() {
        ConnectionFactory connectionFactory = ConnectionFactories.get(DB_CONNECTION);
        connection = Mono.from(connectionFactory.create()).block();
        connection.createStatement(QUERIES.get(0)).execute();
    }

    @Trace(dispatcher = true)
    private void connection3() {
        ConnectionFactory connectionFactory = ConnectionFactories.get(DB_CONNECTION);
        connection = Mono.from(connectionFactory.create()).block();
        Mono.from(connection.createBatch().add(QUERIES.get(0)).execute()).block();
    }


    @Trace(dispatcher = true)
    private void connection4() {
        ConnectionFactory connectionFactory = ConnectionFactories.get(DB_CONNECTION);
        connection = Mono.from(connectionFactory.create()).block();
        Flux.from(connection.createBatch().add(QUERIES.get(0)).execute()).blockFirst();
    }

    @Trace(dispatcher = true)
    private void connection5() {
        ConnectionFactory connectionFactory = ConnectionFactories.get(DB_CONNECTION);
        connection = Mono.from(connectionFactory.create()).block();
        connection.createBatch().add(QUERIES.get(0)).execute();
    }
}
