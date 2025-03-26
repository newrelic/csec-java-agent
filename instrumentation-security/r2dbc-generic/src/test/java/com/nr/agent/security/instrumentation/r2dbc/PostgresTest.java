package com.nr.agent.security.instrumentation.r2dbc;

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
import org.testcontainers.containers.PostgreSQLContainer;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.io.IOException;
import java.net.ServerSocket;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;


@RunWith(SecurityInstrumentationTestRunner.class)
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@InstrumentationTestConfig(includePrefixes = "io.r2dbc.spi")
public class PostgresTest {
    private static PostgreSQLContainer<?> postgres;
    private static Connection connection;
    private static final List<String> QUERIES = new ArrayList<>();
    private static String DB_CONNECTION;

    @BeforeClass
    public static void setup() {
        QUERIES.add("CREATE TABLE IF NOT EXISTS USERS(id int primary key, first_name varchar(255), last_name varchar(255))");

        postgres = new PostgreSQLContainer<>("postgres:9.6");
        postgres.setPortBindings(Collections.singletonList(SecurityInstrumentationTestRunner.getIntrospector().getRandomPort() + ":5432"));
        postgres.start();

        DB_CONNECTION = postgres.getJdbcUrl()
                .replace("jdbc", "r2dbc")
                .replace("localhost", String.format("%s:%s@localhost", postgres.getUsername(), postgres.getPassword()));
    }

    @AfterClass
    public static void stop() {
        postgres.stop();
    }
    @After
    public void teardown() {
        connection.close();
    }

    @Test
    public void testCreateStatement() {
        connection();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertNotNull("No operations detected", operations);

        SQLOperation operation = (SQLOperation) operations.get(2);
        Assert.assertEquals("Wrong event category.", VulnerabilityCaseType.SQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Wrong method-Name.", R2dbcHelper.METHOD_EXECUTE, operation.getMethodName());
        Assert.assertEquals("Wrong executed query.", QUERIES.get(0), operation.getQuery());
    }

    @Test
    public void testCreateStatement1() {
        connection1();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertNotNull("No operations detected", operations);

        SQLOperation operation = (SQLOperation) operations.get(2);
        Assert.assertEquals("Wrong event category.", VulnerabilityCaseType.SQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Wrong method-Name.", R2dbcHelper.METHOD_EXECUTE, operation.getMethodName());
        Assert.assertEquals("Wrong executed query.", QUERIES.get(0), operation.getQuery());
    }

    @Test
    public void testCreateStatement2() {
        connection2();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertNotNull("No operations detected", operations);

        SQLOperation operation = (SQLOperation) operations.get(2);
        Assert.assertEquals("Wrong event category.", VulnerabilityCaseType.SQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Wrong method-Name.", R2dbcHelper.METHOD_EXECUTE, operation.getMethodName());
        Assert.assertEquals("Wrong executed query.", QUERIES.get(0), operation.getQuery());
    }

    @Test
    public void testCreateStatement3() {
        connection3();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertNotNull("No operations detected", operations);

        SQLOperation operation = (SQLOperation) operations.get(2);
        Assert.assertEquals("Wrong event category.", VulnerabilityCaseType.SQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Wrong method-Name.", R2dbcHelper.METHOD_EXECUTE, operation.getMethodName());
        Assert.assertEquals("Wrong executed query.", QUERIES.get(0), operation.getQuery());
    }


    @Test
    public void testCreateBatch() {
        connection4();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertNotNull("No operations detected", operations);

        SQLOperation operation = (SQLOperation) operations.get(2);
        Assert.assertEquals("Wrong event category.", VulnerabilityCaseType.SQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Wrong method-Name.", R2dbcHelper.METHOD_EXECUTE, operation.getMethodName());
        Assert.assertEquals("Wrong executed query.", QUERIES.get(0), operation.getQuery());
    }
    @Test
    public void testCreateBatch5() {
        connection5();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertNotNull("No operations detected", operations);

        SQLOperation operation = (SQLOperation) operations.get(2);
        Assert.assertEquals("Wrong event category.", VulnerabilityCaseType.SQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Wrong method-Name.", R2dbcHelper.METHOD_EXECUTE, operation.getMethodName());
        Assert.assertEquals("Wrong executed query.", QUERIES.get(0), operation.getQuery());
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
