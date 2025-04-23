package com.nr.agent.security.instrumentation.r2dbc.mariadb;

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
import org.testcontainers.containers.MariaDBContainer;
import org.testcontainers.containers.MariaDBR2DBCDatabaseContainer;
import org.testcontainers.utility.DockerImageName;
import org.testcontainers.utility.MountableFile;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = "org.mariadb.r2dbc")
public class ConnectionTest {

    private static Connection connection;

    private static final String HOST = "localhost";

    private static int PORT;

    private static final List<String> QUERIES = new ArrayList<>();

    private static final String DB_NAME = "test";

    private static String DB_USER;

    private static String DB_PASSWORD;

    private static MariaDBContainer<?> mariaDb;

    @BeforeClass
    public static void setUpDb() {
        QUERIES.add("INSERT INTO USERS(id, first_name, last_name) VALUES(1, 'Max', 'Power')");
        QUERIES.add("SELECT * FROM USERS");

        PORT = SecurityInstrumentationTestRunner.getIntrospector().getRandomPort();
        mariaDb = new MariaDBContainer<>(DockerImageName.parse("mariadb:10.5.5"));
        mariaDb.setPortBindings(Collections.singletonList(PORT + ":3808"));

        mariaDb.withCopyFileToContainer(MountableFile.forClasspathResource("users.sql"), "/var/lib/mysql/");
        mariaDb.start();

        ConnectionFactoryOptions mariaDbOption = MariaDBR2DBCDatabaseContainer.getOptions(mariaDb);
        PORT = (Integer) mariaDbOption.getValue(ConnectionFactoryOptions.PORT);
        DB_PASSWORD = (String) mariaDbOption.getValue(ConnectionFactoryOptions.PASSWORD);
        DB_USER = (String) mariaDbOption.getValue(ConnectionFactoryOptions.USER);
    }

    @AfterClass
    public static void tearDownDb() {
        if (mariaDb != null && mariaDb.isCreated()) {
            mariaDb.stop();
        }
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
                MariaDBR2DBCDatabaseContainer.getOptions(mariaDb)
        );

        connection = Mono.from(connectionFactory.create()).block();
    }

    private void connect1() {
        ConnectionFactory connectionFactory = new MariadbConnectionFactory(
                MariadbConnectionConfiguration.builder()
                        .host(HOST)
                        .port(PORT)
                        .database(DB_NAME)
                        .username(DB_USER)
                        .password(DB_PASSWORD)
                        .build()
        );
        connection = Mono.from(connectionFactory.create()).block();
    }
    private void connect2() {
        String url = mariaDb.getJdbcUrl()
                .replace("mysql", "mariadb")
                .replace("jdbc", "r2dbc")
                .replace(HOST, String.format("%s:%s@localhost", DB_NAME, DB_PASSWORD));

        ConnectionFactory connectionFactory = ConnectionFactories.get(url);
        connection = Mono.from(connectionFactory.create()).block();
    }
}