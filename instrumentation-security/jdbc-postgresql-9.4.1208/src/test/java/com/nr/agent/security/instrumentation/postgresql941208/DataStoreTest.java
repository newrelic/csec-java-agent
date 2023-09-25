package com.nr.agent.security.instrumentation.postgresql941208;

import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.api.agent.Trace;
import com.newrelic.api.agent.security.schema.JDBCVendor;
import com.newrelic.security.test.marker.Java12IncompatibleTest;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.ClassRule;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;
import org.postgresql.ds.PGConnectionPoolDataSource;
import org.postgresql.ds.PGPoolingDataSource;
import org.postgresql.ds.PGSimpleDataSource;
import org.postgresql.ds.common.BaseDataSource;
import org.postgresql.jdbc2.optional.ConnectionPool;
import org.postgresql.jdbc2.optional.PoolingDataSource;
import org.postgresql.jdbc2.optional.SimpleDataSource;
import org.postgresql.jdbc3.Jdbc3ConnectionPool;
import org.postgresql.jdbc3.Jdbc3PoolingDataSource;
import org.postgresql.jdbc3.Jdbc3SimpleDataSource;
import org.postgresql.xa.PGXADataSource;
import org.testcontainers.containers.PostgreSQLContainer;

import java.sql.Connection;
import java.sql.SQLException;

@Category({ Java12IncompatibleTest.class })
@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = "org.postgresql")
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class DataStoreTest {
    private static final String DB_USER = "postgres";
    private static final String DB_PASSWORD = "postgres";
    private static final String DB_NAME = "test";
    @ClassRule
    public static PostgreSQLContainer postgreSQLContainer = new PostgreSQLContainer("postgres:11.1")
            .withDatabaseName(DB_NAME)
            .withUsername(DB_USER)
            .withPassword(DB_PASSWORD);

    @AfterClass
    public static void cleanup() throws SQLException {
        if (postgreSQLContainer != null) {
            postgreSQLContainer.close();
        }
    }

    @Test
    public void testGetConnectionConnectionPool() throws SQLException {
        callGetConnectionConnectionPool();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String vendor = introspector.getJDBCVendor();
        Assert.assertEquals("Incorrect DB vendor", vendor, JDBCVendor.POSTGRES);
    }

    @Test
    public void testGetConnectionConnectionPool1() throws SQLException {
        callGetConnectionConnectionPool1();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String vendor = introspector.getJDBCVendor();
        Assert.assertEquals("Incorrect DB vendor", vendor, JDBCVendor.POSTGRES);
    }


    @Test
    public void testGetConnectionJdbc3ConnectionPool() throws SQLException {
        callJdbc3ConnectionPool();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String vendor = introspector.getJDBCVendor();
        Assert.assertEquals("Incorrect DB vendor", JDBCVendor.POSTGRES, vendor);
    }

    @Test
    public void testGetConnectionJdbc3ConnectionPool1() throws SQLException {
        callJdbc3ConnectionPool1();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String vendor = introspector.getJDBCVendor();
        Assert.assertEquals("Incorrect DB vendor", JDBCVendor.POSTGRES, vendor);
    }

    @Test
    public void testGetConnectionJdbc3PoolingDataSource() throws SQLException {
        callJdbc3PoolingDataSource();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String vendor = introspector.getJDBCVendor();
        Assert.assertEquals("Incorrect DB vendor", JDBCVendor.POSTGRES, vendor);
    }

    @Test
    public void testGetConnectionJdbc3PoolingDataSource1() throws SQLException {
        callJdbc3PoolingDataSource1();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String vendor = introspector.getJDBCVendor();
        Assert.assertEquals("Incorrect DB vendor", JDBCVendor.POSTGRES, vendor);
    }

    @Test
    public void testGetConnectionJdbc3SimpleDataSource() throws SQLException {
        callJdbc3SimpleDataSource();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String vendor = introspector.getJDBCVendor();
        Assert.assertEquals("Incorrect DB vendor", JDBCVendor.POSTGRES, vendor);
    }

    @Test
    public void testGetConnectionJdbc3SimpleDataSource1() throws SQLException {
        callJdbc3SimpleDataSource1();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String vendor = introspector.getJDBCVendor();
        Assert.assertEquals("Incorrect DB vendor", JDBCVendor.POSTGRES, vendor);
    }

    @Test
    public void testGetConnectionPGConnectionPoolDataSource() throws SQLException {
        callPGConnectionPoolDataSource();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String vendor = introspector.getJDBCVendor();
        Assert.assertEquals("Incorrect DB vendor", JDBCVendor.POSTGRES, vendor);
    }

    @Test
    public void testGetConnectionPGConnectionPoolDataSource1() throws SQLException {
        callPGConnectionPoolDataSource1();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String vendor = introspector.getJDBCVendor();
        Assert.assertEquals("Incorrect DB vendor", JDBCVendor.POSTGRES, vendor);
    }

    @Test
    public void testGetConnectionPGPoolingDataSource() throws SQLException {
        callPGPoolingDataSource();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String vendor = introspector.getJDBCVendor();
        Assert.assertEquals("Incorrect DB vendor", JDBCVendor.POSTGRES, vendor);
    }

    @Test
    public void testGetConnectionPGPoolingDataSource1() throws SQLException {
        callPGPoolingDataSource1();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String vendor = introspector.getJDBCVendor();
        Assert.assertEquals("Incorrect DB vendor", JDBCVendor.POSTGRES, vendor);
    }

    @Test
    public void testGetConnectionPGSimpleDataSource() throws SQLException {
        callPGSimpleDataSource();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String vendor = introspector.getJDBCVendor();
        Assert.assertEquals("Incorrect DB vendor", JDBCVendor.POSTGRES, vendor);
    }

    @Test
    public void testGetConnectionPGSimpleDataSource1() throws SQLException {
        callPGSimpleDataSource1();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String vendor = introspector.getJDBCVendor();
        Assert.assertEquals("Incorrect DB vendor", JDBCVendor.POSTGRES, vendor);
    }

    @Test
    public void testGetConnectionPGXADataSource() throws SQLException {
        callPGXADataSource();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String vendor = introspector.getJDBCVendor();
        Assert.assertEquals("Incorrect DB vendor", JDBCVendor.POSTGRES, vendor);
    }

    @Test
    public void testGetConnectionPGXADataSource1() throws SQLException {
        callPGXADataSource1();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String vendor = introspector.getJDBCVendor();
        Assert.assertEquals("Incorrect DB vendor", JDBCVendor.POSTGRES, vendor);
    }

    @Test
    public void testGetConnectionSimpleDataSource() throws SQLException {
        callSimpleDataSource();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String vendor = introspector.getJDBCVendor();
        Assert.assertEquals("Incorrect DB vendor", JDBCVendor.POSTGRES, vendor);
    }

    @Test
    public void testGetConnectionSimpleDataSource1() throws SQLException {
        callSimpleDataSource1();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String vendor = introspector.getJDBCVendor();
        Assert.assertEquals("Incorrect DB vendor", JDBCVendor.POSTGRES, vendor);
    }

    @Test
    public void testGetConnectionPoolingDataSource() throws SQLException {
        callPoolingDataSource();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String vendor = introspector.getJDBCVendor();
        Assert.assertEquals("Incorrect DB vendor", JDBCVendor.POSTGRES, vendor);
    }

    @Test
    public void testGetConnectionPoolingDataSource1() throws SQLException {
        callPoolingDataSource1();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String vendor = introspector.getJDBCVendor();
        Assert.assertEquals("Incorrect DB vendor", JDBCVendor.POSTGRES, vendor);
    }

    @Trace(dispatcher = true)
    private void callGetConnectionConnectionPool() throws SQLException {
        getConnection(new ConnectionPool());
    }

    @Trace(dispatcher = true)
    private void callGetConnectionConnectionPool1() throws SQLException {
        getConnection1(new ConnectionPool());
    }

    @Trace(dispatcher = true)
    private void callJdbc3ConnectionPool() throws SQLException {
        getConnection(new Jdbc3ConnectionPool());
    }

    @Trace(dispatcher = true)
    private void callJdbc3ConnectionPool1() throws SQLException {
        getConnection1(new Jdbc3ConnectionPool());
    }

    @Trace(dispatcher = true)
    private void callJdbc3PoolingDataSource() throws SQLException {
        getConnection(new Jdbc3PoolingDataSource());
    }

    @Trace(dispatcher = true)
    private void callJdbc3PoolingDataSource1() throws SQLException {
        getConnection1(new Jdbc3PoolingDataSource());
    }

    @Trace(dispatcher = true)
    private void callJdbc3SimpleDataSource() throws SQLException {
        getConnection(new Jdbc3SimpleDataSource());
    }

    @Trace(dispatcher = true)
    private void callJdbc3SimpleDataSource1() throws SQLException {
        getConnection1(new Jdbc3SimpleDataSource());
    }

    @Trace(dispatcher = true)
    private void callPGConnectionPoolDataSource() throws SQLException {
        getConnection(new PGConnectionPoolDataSource());
    }

    @Trace(dispatcher = true)
    private void callPGConnectionPoolDataSource1() throws SQLException {
        getConnection1(new PGConnectionPoolDataSource());
    }

    @Trace(dispatcher = true)
    private void callPGPoolingDataSource() throws SQLException {
        getConnection(new PGPoolingDataSource());
    }

    @Trace(dispatcher = true)
    private void callPGPoolingDataSource1() throws SQLException {
        getConnection1(new PGPoolingDataSource());
    }

    @Trace(dispatcher = true)
    private void callPGSimpleDataSource() throws SQLException {
        getConnection(new PGSimpleDataSource());
    }

    @Trace(dispatcher = true)
    private void callPGSimpleDataSource1() throws SQLException {
        getConnection1(new PGSimpleDataSource());
    }

    @Trace(dispatcher = true)
    private void callPGXADataSource() throws SQLException {
        getConnection(new PGXADataSource());
    }

    @Trace(dispatcher = true)
    private void callPGXADataSource1() throws SQLException {
        getConnection1(new PGXADataSource());
    }

    @Trace(dispatcher = true)
    private void callSimpleDataSource() throws SQLException {
        getConnection(new SimpleDataSource());
    }

    @Trace(dispatcher = true)
    private void callSimpleDataSource1() throws SQLException {
        getConnection1(new SimpleDataSource());
    }

    @Trace(dispatcher = true)
    private void callPoolingDataSource() throws SQLException {
        getConnection(new PoolingDataSource());
    }

    @Trace(dispatcher = true)
    private void callPoolingDataSource1() throws SQLException {
        getConnection1(new PoolingDataSource());
    }

    private void getConnection(BaseDataSource baseDataSource) throws SQLException {
        baseDataSource.setDatabaseName(DB_NAME);
        baseDataSource.setPortNumber(postgreSQLContainer.getMappedPort(5432));
        Connection conn = null;

        try {
            conn = baseDataSource.getConnection(DB_USER, DB_PASSWORD);
        } catch (Exception e) {
            System.out.println("Error in DB connection");
        } finally {
            if (conn!=null) {
                conn.close();
            }
        }
    }

    private void getConnection1(BaseDataSource baseDataSource) throws SQLException {
        baseDataSource.setUser(DB_USER);
        baseDataSource.setPassword(DB_PASSWORD);
        baseDataSource.setDatabaseName(DB_NAME);
        baseDataSource.setPortNumber(postgreSQLContainer.getMappedPort(5432));
        Connection conn = null;

        try {
            conn = baseDataSource.getConnection();
        } catch (Exception e) {
            System.out.println("Error in DB connection"+e);
        } finally {
            if (conn!=null) {
                conn.close();
            }
        }
    }
}
