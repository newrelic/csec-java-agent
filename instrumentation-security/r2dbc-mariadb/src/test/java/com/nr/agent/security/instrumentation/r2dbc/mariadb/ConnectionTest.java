package com.nr.agent.security.instrumentation.r2dbc.mariadb;

import ch.vorburger.mariadb4j.DB;
import ch.vorburger.mariadb4j.DBConfigurationBuilder;
import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.api.agent.Trace;
import com.newrelic.api.agent.security.schema.R2DBCVendor;
import io.r2dbc.spi.Connection;
import io.r2dbc.spi.ConnectionFactories;
import io.r2dbc.spi.ConnectionFactory;
import io.r2dbc.spi.ConnectionFactoryOptions;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mariadb.r2dbc.MariadbConnectionConfiguration;
import org.mariadb.r2dbc.MariadbConnectionFactory;
import org.mariadb.r2dbc.MariadbConnectionFactoryProvider;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.List;

@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = "org.mariadb.r2dbc")
public class ConnectionTest {

    public static DBConfigurationBuilder builder;
    public static DB mariaDb;
    public static Connection connection;
    private static final String DB_USER = "user";
    private static final String DB_PASSWORD = "password";
    private static final String HOST = "localhost";
    private static int PORT;
    private static final List<String> QUERIES = new ArrayList<>();
    private static final String DB_NAME = "test";

    @BeforeClass
    public static void setup() throws Exception {
        QUERIES.add("INSERT INTO USERS(id, first_name, last_name) VALUES(1, 'Max', 'Power')");
        QUERIES.add("SELECT * FROM USERS");

        builder = DBConfigurationBuilder.newBuilder().setPort(0);
        mariaDb = DB.newEmbeddedDB(builder.build());
        mariaDb.start();
        mariaDb.createDB(DB_NAME);
        mariaDb.source("users.sql", DB_USER, DB_PASSWORD, DB_NAME);
        PORT = builder.getPort();
    }

    @AfterClass
    public static void stop() throws Exception {
        if (mariaDb!=null)
            mariaDb.stop();
    }

    @After
    public void teardown() {
        Mono.from(connection.close()).block();
    }


    @Test
    public void testConnect(){
        setConnection();
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        Assert.assertEquals("Wrong R2DBCVendor vendor", introspector.getR2DBCVendor(), R2DBCVendor.MARIA_DB);
    }

    @Test
    public void testConnect1(){
        setConnection1();
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        Assert.assertEquals("Wrong R2DBCVendor vendor", introspector.getR2DBCVendor(), R2DBCVendor.MARIA_DB);
    }

    @Test
    public void testConnect2(){
        setConnection2();
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        Assert.assertEquals("Wrong R2DBCVendor vendor", introspector.getR2DBCVendor(), R2DBCVendor.MARIA_DB);
    }

    @Trace(dispatcher = true)
    private void setConnection(){
        connect();
        Mono.from(connection.createStatement(QUERIES.get(0)).execute()).block();
    }

    @Trace(dispatcher = true)
    private void setConnection1(){
        connect1();
        Mono.from(connection.createStatement(QUERIES.get(1)).execute()).block();
    }

    @Trace(dispatcher = true)
    private void setConnection2(){
        connect2();
        Mono.from(connection.createStatement(QUERIES.get(1)).execute()).block();
    }

    private void connect() {
        ConnectionFactory connectionFactory = new MariadbConnectionFactoryProvider().create(
                ConnectionFactoryOptions.builder()
                        .option(ConnectionFactoryOptions.DRIVER, "mariadb")
                        .option(ConnectionFactoryOptions.PORT, PORT)
                        .option(ConnectionFactoryOptions.SSL, false)
                        .option(ConnectionFactoryOptions.USER, DB_USER)
                        .option(ConnectionFactoryOptions.PASSWORD, DB_PASSWORD)
                        .option(ConnectionFactoryOptions.HOST, HOST)
                        .option(ConnectionFactoryOptions.DATABASE, DB_NAME)
                        .build()
        );

        connection = Mono.from(connectionFactory.create()).block();
    }

    private void connect1() {
        ConnectionFactory connectionFactory = new MariadbConnectionFactory(
                MariadbConnectionConfiguration.builder()
                        .host(HOST)
                        .port(builder.getPort())
                        .database(DB_NAME)
                        .username(DB_USER)
                        .password(DB_PASSWORD)
                        .build()
        );
        connection = Mono.from(connectionFactory.create()).block();
    }
    private void connect2() {
        String url = builder.getURL(DB_NAME)
                .replace("mysql", "mariadb")
                .replace("jdbc", "r2dbc")
                .replace(HOST, "user:password@localhost");

        ConnectionFactory connectionFactory = ConnectionFactories.get(url);
        connection = Mono.from(connectionFactory.create()).block();
    }
}