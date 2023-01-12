package com.nr.agent.instrumentation.jdbc.hs;

import com.newrelic.agent.deps.org.jetbrains.annotations.NotNull;
import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.api.agent.Trace;
import com.newrelic.api.agent.security.schema.JDBCVendor;
import org.hsqldb.jdbc.JDBCDataSource;
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
public class HSql229DataStoreTest {
    private static final String DB_NAME = "test";
    private static final String DB_USER = "sa";
    private static final String DB_PASSWORD = "";

    @Test
    public void testGetConnectionJDBCDataSource() throws SQLException {
        callGetConnectionJDBCDataSource();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String vendor = introspector.getJDBCVendor();
        Assert.assertEquals("Incorrect DB vendor", JDBCVendor.HSQLDB, vendor);
    }

    @Test
    public void testGetConnectionJDBCDataSource1() throws SQLException {
        callGetConnectionJDBCDataSource1();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String vendor = introspector.getJDBCVendor();
        Assert.assertEquals("Incorrect DB vendor", JDBCVendor.HSQLDB, vendor);
    }

    @Trace(dispatcher = true)
    private void callGetConnectionJDBCDataSource() throws SQLException {
        getConnection(new JDBCDataSource());
    }

    @Trace(dispatcher = true)
    private void callGetConnectionJDBCDataSource1() throws SQLException {
        getConnection1(new JDBCDataSource());
    }

    private void getConnection(@NotNull JDBCDataSource baseDataSource) throws SQLException {
        baseDataSource.setDatabase(DB_NAME);
        Connection conn = null;

        try {
            conn = baseDataSource.getConnection(DB_USER, DB_PASSWORD);
        } catch (Exception e) {
            System.out.println("Error in DB connection "+e);
        } finally {
            if (conn!=null) {
                conn.close();
            }
        }
    }

    private void getConnection1(@NotNull JDBCDataSource baseDataSource) throws SQLException {
        baseDataSource.setDatabase(DB_NAME);
        baseDataSource.setUser(DB_USER);
        baseDataSource.setPassword(DB_PASSWORD);
        Connection conn = null;

        try {
            conn = baseDataSource.getConnection();
        } catch (Exception e) {
            System.out.println("Error in DB connection "+e);
        } finally {
            if (conn!=null) {
                conn.close();
            }
        }
    }
}
