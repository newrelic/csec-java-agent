package com.nr.agent.security.instrumentation.r2dbc.mysql;

import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.api.agent.Trace;
import com.newrelic.api.agent.security.schema.R2DBCVendor;
import dev.miku.r2dbc.mysql.MySqlConnectionFactoryProvider;
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
import org.testcontainers.containers.MySQLContainer;
import org.testcontainers.containers.MySQLR2DBCDatabaseContainer;
import org.testcontainers.utility.DockerImageName;
import org.testcontainers.utility.MountableFile;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = "dev.miku.r2dbc.mysql")
public class ConnectionTest {

    private static Connection connection;

    private static int PORT;

    private static final List<String> QUERIES = new ArrayList<>();

    private static String DB_NAME;

    private static String DB_USER;

    private static String DB_PASSWORD;

    private static MySQLContainer<?> mysql;

    @BeforeClass
    public static void setUpDb() {
        QUERIES.add("INSERT INTO USERS(id, first_name, last_name) VALUES(1, 'Max', 'Power')");
        QUERIES.add("SELECT * FROM USERS");

        PORT = SecurityInstrumentationTestRunner.getIntrospector().getRandomPort();
        mysql = new MySQLContainer<>(DockerImageName.parse("mysql:8.4.0"));
        mysql.setPortBindings(Collections.singletonList(PORT + ":3808"));

        mysql.withCopyFileToContainer(MountableFile.forClasspathResource("users.sql"), "/docker-entrypoint-initdb.d/");
        mysql.start();

        ConnectionFactoryOptions mariaDbOption = MySQLR2DBCDatabaseContainer.getOptions(mysql);
        PORT = (Integer) mariaDbOption.getValue(ConnectionFactoryOptions.PORT);
        DB_PASSWORD = (String) mariaDbOption.getValue(ConnectionFactoryOptions.PASSWORD);
        DB_USER = (String) mariaDbOption.getValue(ConnectionFactoryOptions.USER);
        DB_NAME = (String) mariaDbOption.getValue(ConnectionFactoryOptions.DATABASE);
    }

    @AfterClass
    public static void tearDownDb() {
        if (mysql != null && mysql.isCreated()) {
            mysql.stop();
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
        Assert.assertEquals("Wrong R2DBCVendor vendor", introspector.getR2DBCVendor(), R2DBCVendor.MYSQL);
    }

    @Test
    public void testConnect1(){
        setConnection1();
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        Assert.assertEquals("Wrong R2DBCVendor vendor", introspector.getR2DBCVendor(), R2DBCVendor.MYSQL);
    }

    @Trace(dispatcher = true)
    private void setConnection(){
        connect();
        Mono.from(connection.createStatement(QUERIES.get(0)).execute()).block();
        Mono.from(connection.close()).block();
    }

    @Trace(dispatcher = true)
    private void setConnection1(){
        connect1();
        Mono.from(connection.createStatement(QUERIES.get(1)).execute()).block();
        Mono.from(connection.close()).block();
    }

    private void connect() {
        ConnectionFactory connectionFactory = new MySqlConnectionFactoryProvider().create(
                MySQLR2DBCDatabaseContainer.getOptions(mysql)
        );

        connection = Mono.from(connectionFactory.create()).block();
    }

    private void connect1() {
        String DB_CONNECTION = String.format("r2dbc:mysql://%s:%s@localhost:%s/%s?useSSL=false", DB_USER, DB_PASSWORD, PORT, DB_NAME);
        ConnectionFactory connectionFactory = ConnectionFactories.get(DB_CONNECTION);
        connection = Mono.from(connectionFactory.create()).block();
    }

}