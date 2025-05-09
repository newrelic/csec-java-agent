package org.mariadb.jdbc;

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
import org.mariadb.jdbc.internal.common.QueryException;
import org.mariadb.jdbc.internal.mysql.MySQLProtocol;
import org.testcontainers.containers.MariaDBContainer;
import org.testcontainers.utility.DockerImageName;
import org.testcontainers.utility.MountableFile;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Properties;

@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = {"org.mariadb.jdbc"})
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class MariaDb117Test {

    private static String connectionString;

    private static String DB_USER;

    private static String DB_PASSWORD;

    private static int PORT;

    private static MariaDBContainer<?> mariaDb;

    @BeforeClass
    public static void setUpDb() {

        PORT = SecurityInstrumentationTestRunner.getIntrospector().getRandomPort();
        mariaDb = new MariaDBContainer<>(DockerImageName.parse("mariadb:10.5.5"));
        mariaDb.setPortBindings(Collections.singletonList(PORT + ":3808"));

        mariaDb.withCopyFileToContainer(MountableFile.forClasspathResource("maria-db-test.sql"), "/var/lib/mysql/");
        mariaDb.start();

        DB_PASSWORD = mariaDb.getPassword();
        DB_USER = mariaDb.getUsername();
        connectionString = mariaDb.getJdbcUrl();
    }

    @AfterClass
    public static void tearDownDb() {
        if (mariaDb != null && mariaDb.isCreated()) {
            mariaDb.stop();
        }
    }
    @Test
    public void testConnect() throws SQLException {
        getConnection();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String vendor = introspector.getJDBCVendor();
        Assert.assertEquals("Incorrect DB vendor", JDBCVendor.MARIA_DB, vendor);
    }

    @Test
    public void testConnect1() throws SQLException, ClassNotFoundException {
        getConnection1();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String vendor = introspector.getJDBCVendor();
        Assert.assertEquals("Incorrect DB vendor", JDBCVendor.MARIA_DB, vendor);
    }

    @Test
    public void testConnect2() throws SQLException {
        getConnection2();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String vendor = introspector.getJDBCVendor();
        Assert.assertEquals("Incorrect DB vendor", JDBCVendor.MARIA_DB, vendor);
    }

    @Test
    public void testConnect3() throws SQLException {
        getConnection3();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String vendor = introspector.getJDBCVendor();
        Assert.assertEquals("Incorrect DB vendor", JDBCVendor.MARIA_DB, vendor);
    }

    @Trace(dispatcher = true)
    private void getConnection() throws SQLException {
        Connection dbConnection = null;

        try {
            Class.forName("org.mariadb.jdbc.Driver");
            dbConnection = DriverManager.getConnection(connectionString, DB_USER, DB_PASSWORD);
        } catch (Exception e) {
            e.printStackTrace();
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
            Class.forName("org.mariadb.jdbc.Driver");
            dbConnection = DriverManager.getConnection(connectionString, info);
        } catch (Exception e) {
            e.printStackTrace();
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
            Class.forName("org.mariadb.jdbc.Driver");
            dbConnection = DriverManager.getConnection(String.format(connectionString + "?user=%s&password=%s", DB_USER, DB_PASSWORD));
        } catch (Exception e) {
            e.printStackTrace();
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
            Class.forName("org.mariadb.jdbc.Driver");
            dbConnection = MySQLConnection.newConnection(new MySQLProtocol(JDBCUrl.parse(connectionString), DB_USER, DB_PASSWORD, new Properties()));
        } catch (Exception e) {
            e.printStackTrace();
        }
        finally {
            if (dbConnection!=null) {
                dbConnection.close();
            }
        }
    }
}
