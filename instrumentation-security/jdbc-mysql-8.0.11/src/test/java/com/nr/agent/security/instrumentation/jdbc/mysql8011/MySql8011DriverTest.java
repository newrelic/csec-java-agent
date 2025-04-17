package com.nr.agent.security.instrumentation.jdbc.mysql8011;

import com.mysql.cj.conf.HostInfo;
import com.mysql.cj.jdbc.ConnectionImpl;
import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.api.agent.Trace;
import com.newrelic.api.agent.security.schema.JDBCVendor;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;
import org.testcontainers.containers.MySQLContainer;
import org.testcontainers.utility.DockerImageName;
import org.testcontainers.utility.MountableFile;

import java.io.IOException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.Collections;
import java.util.Properties;
import java.util.concurrent.TimeUnit;


@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = {"com.mysql.cj"})
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class MySql8011DriverTest {

    private static String DB_CONNECTION;

    private static String DB_USER;

    private static String DB_PASSWORD;

    private static int PORT;

    private static MySQLContainer<?> mysql;

    @BeforeClass
    public static void setUpDb() {
        PORT = SecurityInstrumentationTestRunner.getIntrospector().getRandomPort();
        mysql = new MySQLContainer<>(DockerImageName.parse("mysql:8.4.0"))
                .withCopyFileToContainer(MountableFile.forClasspathResource("maria-db-test.sql"), "/docker-entrypoint-initdb.d/");
        mysql.setPortBindings(Collections.singletonList(PORT + ":3306"));
        mysql.start();

        DB_PASSWORD = mysql.getPassword();
        DB_USER = mysql.getUsername();
        DB_CONNECTION = mysql.getJdbcUrl()+"?useSSL=false";
    }

    @AfterClass
    public static void tearDownDb() {
        if (mysql != null && mysql.isCreated()) {
            mysql.close();
            mysql.stop();
        }
    }

    @Test
    public void testConnect() throws SQLException {
        getConnection();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String vendor = introspector.getJDBCVendor();
        Assert.assertEquals("Incorrect DB vendor", JDBCVendor.MYSQL, vendor);
    }

    @Test
    public void testConnect1() throws SQLException {
        getConnection1();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String vendor = introspector.getJDBCVendor();
        Assert.assertEquals("Incorrect DB vendor", JDBCVendor.MYSQL, vendor);
    }

    @Test
    public void testConnect2() throws SQLException {
        getConnection2();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String vendor = introspector.getJDBCVendor();
        Assert.assertEquals("Incorrect DB vendor", JDBCVendor.MYSQL, vendor);
    }

    @Test
    public void testConnect3() throws SQLException {
        getConnection3();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String vendor = introspector.getJDBCVendor();
        Assert.assertEquals("Incorrect DB vendor", JDBCVendor.MYSQL, vendor);
    }

    @Trace(dispatcher = true)
    private void getConnection() throws SQLException {
        Connection dbConnection = null;

        try {
            Class.forName("com.mysql.cj.jdbc.Driver");
            dbConnection = DriverManager.getConnection(DB_CONNECTION, DB_USER, DB_PASSWORD);
        } catch (Exception ignored) {
        }
        finally {
            if (dbConnection!=null) {
                dbConnection.close();
            }
        }
    }

    @Trace(dispatcher = true)
    private void getConnection1() throws SQLException {
        Connection dbConnection = null;

        try {
            Properties info = new Properties();
            info.put("user", DB_USER);
            info.put("password", DB_PASSWORD);
            Class.forName("com.mysql.cj.jdbc.Driver");
            dbConnection = DriverManager.getConnection(DB_CONNECTION, info);
        } catch (Exception ignored) {
        }
        finally {
            if (dbConnection!=null) {
                dbConnection.close();
            }
        }
    }

    @Trace(dispatcher = true)
    private void getConnection2() throws SQLException {
        Connection dbConnection = null;

        try {
            Class.forName("com.mysql.cj.jdbc.Driver");
            dbConnection = DriverManager.getConnection(DB_CONNECTION);
        } catch (Exception ignored) {
        }
        finally {
            if (dbConnection!=null) {
                dbConnection.close();
            }
        }
    }

    @Trace(dispatcher = true)
    private void getConnection3() throws SQLException {
        Connection dbConnection = null;

        try {
            Class.forName("com.mysql.cj.jdbc.Driver");
            String host = "localhost";
            dbConnection = ConnectionImpl.getInstance(new HostInfo(
                    () -> DB_CONNECTION, host, PORT, DB_USER, DB_PASSWORD, Collections.singletonMap("useSSL", "false")
            ));
        } catch (Exception ignored) {
        }
        finally {
            if (dbConnection!=null) {
                dbConnection.close();
            }
        }
    }
}
