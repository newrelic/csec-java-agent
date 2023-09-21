package com.newrelic.agent.security.instrumentation.jdbc.hs;

import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.api.agent.Trace;
import com.newrelic.api.agent.security.schema.JDBCVendor;
import org.hsqldb.jdbc.JDBCPool;
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
@InstrumentationTestConfig(includePrefixes = "org.hsqldb.jdbc")
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class HSql229PoolTest {
    private static final String DB_CONNECTION = "jdbc:hsqldb:mem:test;DB_CLOSE_DELAY=-1";
    private static final String DB_USER = "sa";
    private static final String DB_PASSWORD = "";
    @Test
    public void testGetConnectionJDBCPool() throws SQLException {
        callGetConnectionJDBCPool();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String vendor = introspector.getJDBCVendor();
        Assert.assertEquals("Incorrect DB vendor", JDBCVendor.HSQLDB, vendor);
    }

    @Test
    public void testGetConnectionJDBCPool1() throws SQLException {
        callGetConnectionJDBCPool1();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String vendor = introspector.getJDBCVendor();
        Assert.assertEquals("Incorrect DB vendor", JDBCVendor.HSQLDB, vendor);
    }

    @Trace(dispatcher = true)
    private void callGetConnectionJDBCPool() throws SQLException {
        getConnection(new JDBCPool());
    }

    @Trace(dispatcher = true)
    private void callGetConnectionJDBCPool1() throws SQLException {
        getConnection1(new JDBCPool());
    }

    private void getConnection(JDBCPool baseDataSource) throws SQLException {
        baseDataSource.setUrl(DB_CONNECTION);
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

    private void getConnection1(JDBCPool baseDataSource) throws SQLException {
        baseDataSource.setUrl(DB_CONNECTION);
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
