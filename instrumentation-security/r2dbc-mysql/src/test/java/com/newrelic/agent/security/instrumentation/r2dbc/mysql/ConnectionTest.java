package com.newrelic.agent.security.instrumentation.r2dbc.mysql;

import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.api.agent.Trace;
import com.newrelic.api.agent.security.schema.R2DBCVendor;
import com.wix.mysql.EmbeddedMysql;
import com.wix.mysql.config.MysqldConfig;
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
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

import static com.wix.mysql.EmbeddedMysql.anEmbeddedMysql;
import static com.wix.mysql.ScriptResolver.classPathScript;
import static com.wix.mysql.config.Charset.UTF8;
import static com.wix.mysql.config.MysqldConfig.aMysqldConfig;
import static com.wix.mysql.distribution.Version.v5_7_latest;

@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = "dev.miku.r2dbc.mysql")
public class ConnectionTest {
    private static EmbeddedMysql mysqld = null;
    public static Connection connection;
    private static final String DB_USER = "user";
    private static final String DB_PASSWORD = "password";
    private final int PORT = mysqld.getConfig().getPort();
    private static final List<String> QUERIES = new ArrayList<>();
    private static final String DB_NAME = "test";
    private static final String HOST = "localhost";


    @BeforeClass
    public static void setup1() throws Exception {
        QUERIES.add("INSERT INTO USERS(id, first_name, last_name) VALUES(1, 'Max', 'Power')");
        QUERIES.add("SELECT * FROM USERS");

        MysqldConfig config = aMysqldConfig(v5_7_latest)
                .withCharset(UTF8)
                .withFreePort()
                .withTimeout(2, TimeUnit.MINUTES)
                .withUser(DB_USER, DB_PASSWORD)
                .build();

        mysqld = anEmbeddedMysql(config)
                .addSchema(DB_NAME, classPathScript("users.sql"))
                .start();
    }

    @AfterClass
    public static void stop() {
        if (mysqld!=null)
            mysqld.stop();
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
                ConnectionFactoryOptions.
                        builder()
                        .option(ConnectionFactoryOptions.DRIVER, "mysql")
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
        String DB_CONNECTION = "r2dbc:mysql://user:password@localhost:" + PORT + "/" + DB_NAME + "?useSSL=false";
        ConnectionFactory connectionFactory = ConnectionFactories.get(DB_CONNECTION);
        connection = Mono.from(connectionFactory.create()).block();
    }
}