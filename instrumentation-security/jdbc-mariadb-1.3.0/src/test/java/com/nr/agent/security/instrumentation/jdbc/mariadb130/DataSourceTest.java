package com.nr.agent.security.instrumentation.jdbc.mariadb130;

import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.api.agent.Trace;
import com.newrelic.api.agent.security.schema.JDBCVendor;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mariadb.jdbc.MariaDbDataSource;
import org.testcontainers.containers.MariaDBContainer;
import org.testcontainers.utility.DockerImageName;
import org.testcontainers.utility.MountableFile;

import java.sql.Connection;
import java.sql.SQLException;
import java.util.Collections;

@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = {"org.mariadb.jdbc"})
public class DataSourceTest {
    private static String connectionString;

    private static String dbName;

    private static String DB_USER;

    private static String DB_PASSWORD;

    public static MariaDBContainer<?> mariaDb;

    private static int PORT;

    @BeforeClass
    public static void setUpDb() {

        PORT = SecurityInstrumentationTestRunner.getIntrospector().getRandomPort();
        mariaDb = new MariaDBContainer<>(DockerImageName.parse("mariadb:10.5.5"));
        mariaDb.setPortBindings(Collections.singletonList(PORT + ":3808"));

        mariaDb.withCopyFileToContainer(MountableFile.forClasspathResource("maria-db-test.sql"), "/var/lib/mysql/");
        mariaDb.start();

        DB_PASSWORD = mariaDb.getPassword();
        DB_USER = mariaDb.getUsername();
        dbName = mariaDb.getDatabaseName();
        connectionString = mariaDb.getJdbcUrl();
    }

    @AfterClass
    public static void tearDownDb() {
        if (mariaDb != null && mariaDb.isCreated()) {
            mariaDb.stop();
        }
    }
    @Test
    public void testConnection() throws SQLException {
        getConnection( new MariaDbDataSource());

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String vendor = introspector.getJDBCVendor();
        Assert.assertEquals("Incorrect DB vendor", JDBCVendor.MARIA_DB, vendor);
    }

    @Test
    public void testConnection1() throws SQLException {
        getConnection1(new MariaDbDataSource());

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String vendor = introspector.getJDBCVendor();
        Assert.assertEquals("Incorrect DB vendor", JDBCVendor.MARIA_DB, vendor);
    }

    @Test
    public void testConnection2() throws SQLException {
        getConnection( new MariaDbDataSource(connectionString));

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String vendor = introspector.getJDBCVendor();
        Assert.assertEquals("Incorrect DB vendor", JDBCVendor.MARIA_DB, vendor);
    }

    @Test
    public void testConnection3() throws SQLException {
        getConnection1(new MariaDbDataSource(connectionString));

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String vendor = introspector.getJDBCVendor();
        Assert.assertEquals("Incorrect DB vendor", JDBCVendor.MARIA_DB, vendor);
    }

    @Test
    public void testConnection4() throws SQLException {
        getConnection( new MariaDbDataSource("localhost", PORT, dbName));

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String vendor = introspector.getJDBCVendor();
        Assert.assertEquals("Incorrect DB vendor", JDBCVendor.MARIA_DB, vendor);
    }

    @Test
    public void testConnection5() throws SQLException {
        getConnection1(new MariaDbDataSource("localhost", PORT, dbName));

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String vendor = introspector.getJDBCVendor();
        Assert.assertEquals("Incorrect DB vendor", JDBCVendor.MARIA_DB, vendor);
    }

    @Trace(dispatcher = true)
    private void getConnection(MariaDbDataSource dataSource) throws SQLException {
        Connection dbConnection = null;

        dataSource.setUrl(connectionString);
        dataSource.setUser(DB_USER);
        dataSource.setPassword(DB_PASSWORD);
        try {
            Class.forName("org.mariadb.jdbc.Driver");
            dbConnection = dataSource.getConnection();
            dbConnection.close();
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
    private void getConnection1(MariaDbDataSource dataSource) throws SQLException {
        Connection dbConnection = null;
        dataSource.setUrl(connectionString);
        try {
            Class.forName("org.mariadb.jdbc.Driver");
            dbConnection = dataSource.getConnection(DB_USER, DB_PASSWORD);
            dbConnection.close();
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
