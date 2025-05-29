package com.nr.agent.security.instrumentation.r2dbc.postgres;

import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.api.agent.Trace;
import com.newrelic.api.agent.security.schema.R2DBCVendor;
import io.r2dbc.postgresql.PostgresqlConnectionConfiguration;
import io.r2dbc.postgresql.PostgresqlConnectionFactory;
import io.r2dbc.postgresql.PostgresqlConnectionFactoryProvider;
import io.r2dbc.spi.Connection;
import io.r2dbc.spi.ConnectionFactories;
import io.r2dbc.spi.ConnectionFactory;
import io.r2dbc.spi.ConnectionFactoryOptions;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;
import org.testcontainers.containers.PostgreSQLContainer;
import reactor.core.publisher.Mono;

import java.io.IOException;
import java.net.ServerSocket;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

@RunWith(SecurityInstrumentationTestRunner.class)
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@InstrumentationTestConfig(includePrefixes = "io.r2dbc.postgresql")
public class ConnectionTest {

    private static PostgreSQLContainer<?> postgres;
    private static Connection connection;
    private static String DB_USER = "user";
    private static String DB_PASSWORD = "password";
    private static String DB_NAME = "test";
    private static final String HOST = "localhost";
    private static final List<String> QUERIES = new ArrayList<>();
    private static int PORT;

    @BeforeClass
    public static void setup() {
        PORT = SecurityInstrumentationTestRunner.getIntrospector().getRandomPort();
        QUERIES.add("CREATE TABLE IF NOT EXISTS USERS(id int primary key, first_name varchar(255), last_name varchar(255))");
        QUERIES.add("INSERT INTO USERS(id, first_name, last_name) VALUES(1, 'Max', 'Power')");
        QUERIES.add("SELECT * FROM USERS");

        postgres = new PostgreSQLContainer<>("postgres:9.6");
        postgres.setPortBindings(Collections.singletonList(PORT + ":5432"));
        postgres.start();
        DB_NAME = postgres.getDatabaseName();
        DB_USER = postgres.getUsername();
        DB_PASSWORD = postgres.getPassword();
    }

    @After
    public void teardown() {
        Mono.from(connection.close()).block();
    }

    @AfterClass
    public static void stop() {
        if (postgres!=null)
            postgres.stop();
    }

    @Test
    public void testConnect(){
        setConnection();
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        Assert.assertEquals("Wrong R2DBCVendor vendor", introspector.getR2DBCVendor(), R2DBCVendor.POSTGRES);
    }

    @Test
    public void testConnect1(){
        setConnection1();
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        Assert.assertEquals("Wrong R2DBCVendor vendor", introspector.getR2DBCVendor(), R2DBCVendor.POSTGRES);
    }

    @Test
    public void testConnect2(){
        setConnection2();
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        Assert.assertEquals("Wrong R2DBCVendor vendor", introspector.getR2DBCVendor(), R2DBCVendor.POSTGRES);
    }

    @Trace(dispatcher = true)
    private void setConnection(){
        connect();
        Mono.from(connection.createStatement(QUERIES.get(1)).execute()).block();
        Mono.from(connection.close()).block();
    }

    @Trace(dispatcher = true)
    private void setConnection1(){
        connect1();
        Mono.from(connection.createStatement(QUERIES.get(2)).execute()).block();
        Mono.from(connection.close()).block();
    }

    @Trace(dispatcher = true)
    private void setConnection2(){
        connect2();
        Mono.from(connection.createStatement(QUERIES.get(2)).execute()).block();
        Mono.from(connection.close()).block();
    }

    private void connect() {
        PostgresqlConnectionFactory connectionFactory = new PostgresqlConnectionFactory(
                PostgresqlConnectionConfiguration.builder()
                        .host(HOST)
                        .port(PORT)
                        .database(DB_NAME)
                        .username(DB_USER)
                        .password(DB_PASSWORD)
                        .build()
        );

        connection = Mono.from(connectionFactory.create()).block();
        Mono.from(connection.createStatement(QUERIES.get(0)).execute()).block();
    }

    private void connect1() {
        PostgresqlConnectionFactory connectionFactory = new PostgresqlConnectionFactoryProvider().create(
                ConnectionFactoryOptions.
                        builder()
                        .option(ConnectionFactoryOptions.DRIVER, "postgres")
                        .option(ConnectionFactoryOptions.PORT, PORT)
                        .option(ConnectionFactoryOptions.SSL, false)
                        .option(ConnectionFactoryOptions.USER, DB_USER)
                        .option(ConnectionFactoryOptions.PASSWORD, DB_PASSWORD)
                        .option(ConnectionFactoryOptions.HOST, "localhost")
                        .option(ConnectionFactoryOptions.DATABASE, DB_NAME)
                        .build()
        );

        connection = Mono.from(connectionFactory.create()).block();
        Mono.from(connection.createStatement(QUERIES.get(0)).execute()).block();
    }
    private void connect2() {
            String url = postgres.getJdbcUrl()
                    .replace("jdbc", "r2dbc")
                    .replace(HOST, String.format("%s:%s@%s", DB_USER, DB_PASSWORD, HOST));
            ConnectionFactory connectionFactory = ConnectionFactories.get(url);
            connection = Mono.from(connectionFactory.create()).block();
            Mono.from(connection.createStatement(QUERIES.get(0)).execute()).block();
    }
}