package com.newrelic.agent.security.instrumentation.jdbc.hs;

import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.api.agent.Trace;
import com.newrelic.api.agent.security.schema.JDBCVendor;
import org.hsqldb.jdbc.jdbcDataSource;
import org.junit.Assert;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;

import java.sql.Connection;
import java.sql.SQLException;

/**
 * This is a quick test to allow make sure the unit test framework works with the module testrunner.
 */
@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = "org.hsqldb")
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class HSql1722DataStoreTest {
    private static final String DB_NAME = "test";
    private static final String DB_USER = "sa";
    private static final String DB_PASSWORD = "";

    @Test
    public void testGetConnectionJdbcDataSource() throws SQLException {
        callGetConnectionJdbcDataSource();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String vendor = introspector.getJDBCVendor();
        Assert.assertEquals("Incorrect DB vendor", JDBCVendor.HSQLDB, vendor);
    }

    @Test
    public void testGetConnectionJdbcDataSource1() throws SQLException {
        callGetConnectionJdbcDataSource1();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String vendor = introspector.getJDBCVendor();
        Assert.assertEquals("Incorrect DB vendor", JDBCVendor.HSQLDB, vendor);
    }


    @Trace(dispatcher = true)
    private void callGetConnectionJdbcDataSource() throws SQLException {
        getConnection(new jdbcDataSource());
    }

    @Trace(dispatcher = true)
    private void callGetConnectionJdbcDataSource1() throws SQLException {
        getConnection1(new jdbcDataSource());
    }

    private void getConnection(jdbcDataSource baseDataSource) throws SQLException {
        baseDataSource.setDatabase(DB_NAME);
        Connection conn = null;

        try {
            conn = baseDataSource.getConnection(DB_USER, DB_PASSWORD);
        } catch (Exception e) {
            System.out.println("Error in DB connection " + e);
        } finally {
            if (conn != null) {
                conn.close();
            }
        }
    }

    private void getConnection1(jdbcDataSource baseDataSource) throws SQLException {
        baseDataSource.setDatabase(DB_NAME);
        baseDataSource.setUser(DB_USER);
        baseDataSource.setPassword(DB_PASSWORD);
        Connection conn = null;

        try {
            conn = baseDataSource.getConnection();
        } catch (Exception e) {
            System.out.println("Error in DB connection " + e);
        } finally {
            if (conn!=null) {
                conn.close();
            }
        }
    }
}
