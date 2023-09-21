package com.newrelic.agent.security.instrumentation.jdbc.mariadb117;

import ch.vorburger.mariadb4j.DB;
import ch.vorburger.mariadb4j.DBConfigurationBuilder;
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
import org.mariadb.jdbc.MySQLDataSource;

import java.sql.Connection;
import java.sql.SQLException;

@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = {"org.mariadb.jdbc"})
public class DataSourceTest {
    private static DB mariaDb;
    private static String connectionString;
    private static String dbName;
    private static final String DB_USER = "";
    private static final String DB_PASSWORD = "";

    private static int PORT;
    @BeforeClass
    public static void setUpDb() throws Exception {
        DBConfigurationBuilder builder = DBConfigurationBuilder.newBuilder()
                .setPort(0); // This will automatically find a free port

        PORT = builder.getPort();
        dbName = "MariaDB" + System.currentTimeMillis();
        mariaDb = DB.newEmbeddedDB(builder.build());
        connectionString = builder.getURL(dbName);
        mariaDb.start();

        mariaDb.createDB(dbName);
        mariaDb.source("maria-db-test.sql", null, null, dbName);
    }
    @AfterClass
    public static void tearDownDb() throws Exception {
        mariaDb.stop();
    }

    @Test
    public void testConnection() throws SQLException {
        getConnection( new MySQLDataSource());

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String vendor = introspector.getJDBCVendor();
        Assert.assertEquals("Incorrect DB vendor", JDBCVendor.MARIA_DB, vendor);
    }

    @Test
    public void testConnection1() throws SQLException {
        getConnection1(new MySQLDataSource());

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String vendor = introspector.getJDBCVendor();
        Assert.assertEquals("Incorrect DB vendor", JDBCVendor.MARIA_DB, vendor);
    }


    @Test
    public void testConnection2() throws SQLException {
        getConnection( new MySQLDataSource("localhost", PORT, dbName));

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String vendor = introspector.getJDBCVendor();
        Assert.assertEquals("Incorrect DB vendor", JDBCVendor.MARIA_DB, vendor);
    }

    @Test
    public void testConnection3() throws SQLException {
        getConnection1(new MySQLDataSource("localhost", PORT, dbName));

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String vendor = introspector.getJDBCVendor();
        Assert.assertEquals("Incorrect DB vendor", JDBCVendor.MARIA_DB, vendor);
    }

    @Trace(dispatcher = true)
    private void getConnection(MySQLDataSource dataSource) throws SQLException {
        Connection dbConnection = null;

        dataSource.setUrl(connectionString);
        dataSource.setUser(DB_USER);
        dataSource.setPassword(DB_PASSWORD);
        try {
            Class.forName("org.mariadb.jdbc.Driver");
            dbConnection = dataSource.getConnection();
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
    private void getConnection1(MySQLDataSource dataSource) throws SQLException {
        Connection dbConnection = null;
        dataSource.setUrl(connectionString);
        try {
            Class.forName("org.mariadb.jdbc.Driver");
            dbConnection = dataSource.getConnection(DB_USER, DB_PASSWORD);
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
