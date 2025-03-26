package com.nr.agent.security.instrumentation.postgresql80312;

import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.api.agent.Trace;
import com.newrelic.api.agent.security.schema.JDBCVendor;
import com.newrelic.security.test.marker.Java12IncompatibleTest;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;
import org.testcontainers.containers.PostgreSQLContainer;
import ru.yandex.qatools.embed.postgresql.EmbeddedPostgres;

import java.io.IOException;
import java.net.ServerSocket;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Properties;

import static ru.yandex.qatools.embed.postgresql.distribution.Version.Main.V9_6;

@Category({ Java12IncompatibleTest.class })
@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = "org.postgresql")
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class DriverTest {

    public static PostgreSQLContainer<?> postgres;
    public static Connection connection;
    private static String DB_USER = "user";
    private static String DB_PASSWORD = "password";
    private static String DB_NAME = "test";
    private static final String HOST = "localhost";
    private static final int PORT = getRandomPort();

    @BeforeClass
    public static void setup() {

        postgres = new PostgreSQLContainer<>("postgres:9.6");
        postgres.setPortBindings(Collections.singletonList(PORT + ":5432"));
        postgres.start();
        DB_NAME = postgres.getDatabaseName();
        DB_USER = postgres.getUsername();
        DB_PASSWORD = postgres.getPassword();

    }

    @After
    public void teardown() throws SQLException {
        if (connection!=null) {
            connection.close();
        }
    }

    @AfterClass
    public static void stop() {
        if (postgres!=null)
            postgres.stop();
    }

    @Test
    public void testConnect() throws SQLException {
        getConnection();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String vendor = introspector.getJDBCVendor();
        Assert.assertEquals("Incorrect DB vendor", vendor, JDBCVendor.POSTGRES);
    }

    @Test
    public void testConnect1() throws SQLException {
        getConnection1();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String vendor = introspector.getJDBCVendor();
        Assert.assertEquals("Incorrect DB vendor", vendor, JDBCVendor.POSTGRES);
    }

    @Trace(dispatcher = true)
    private void getConnection() throws SQLException {
        Connection c = null;
        try {
            Class.forName("org.postgresql.Driver");
            c = DriverManager.getConnection(String.format("jdbc:postgresql://%s:%s/%s", HOST, PORT, DB_NAME), DB_USER, DB_PASSWORD);
        } catch (Exception e) {
            System.out.println("Error in DB connection: " + e);
        } finally {
            if (c != null) {
                c.close();
            }
        }
    }

    @Trace(dispatcher = true)
    private void getConnection1() throws SQLException {
        Connection c = null;
        try {
            Class.forName("org.postgresql.Driver");
            Properties info = new Properties();
            info.put("user", DB_USER);
            info.put("password", DB_PASSWORD);
            c = DriverManager.getConnection(String.format("jdbc:postgresql://%s:%s/%s", HOST, PORT, DB_NAME), info);
        } catch (Exception e) {
            System.out.println("Error in DB connection: " + e);
        } finally {
            if (c != null) {
                c.close();
            }
        }
    }

    private static int getRandomPort() {
        int port;
        try {
            ServerSocket socket = new ServerSocket(0);
            port = socket.getLocalPort();
            socket.close();
        } catch (IOException e) {
            throw new RuntimeException("Unable to allocate ephemeral port");
        }
        return port;
    }
}
