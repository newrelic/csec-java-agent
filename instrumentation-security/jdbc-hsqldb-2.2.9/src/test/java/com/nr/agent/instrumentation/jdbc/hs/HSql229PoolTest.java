package com.nr.agent.instrumentation.jdbc.hs;

import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.api.agent.Trace;
import com.newrelic.api.agent.security.schema.JDBCVendor;
import org.hsqldb.jdbc.JDBCPool;
import org.junit.AfterClass;
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
    private static Connection CONNECTION;

    @AfterClass
    public static void teardown() throws SQLException {
        if (CONNECTION!=null) {
            CONNECTION.close();
        }
    }

    @Trace(dispatcher = true)
    private static Connection getDBConnection() throws SQLException {
        Connection dbConnection = null;
        JDBCPool pool = new JDBCPool();
        pool.setUrl(DB_CONNECTION);
        pool.setUser(DB_USER);
        pool.setPassword(DB_PASSWORD);
        Connection conn = null;

        try {
            conn = pool.getConnection();
        } catch (Exception e) {
            System.out.println("Error in DB connection");
        } finally {
            if (conn!=null) {
                conn.close();
            }
        }
        return dbConnection;
    }

    @Trace(dispatcher = true)
    private static Connection getDBConnection1() throws SQLException {
        Connection dbConnection = null;
        JDBCPool pool = new JDBCPool();
        pool.setUrl(DB_CONNECTION);
        Connection conn = null;

        try {
            conn = pool.getConnection(DB_USER, DB_PASSWORD);
        } catch (Exception e) {
            System.out.println("Error in DB connection");
        } finally {
            if (conn!=null) {
                conn.close();
            }
        }
        return dbConnection;
    }

    @Test
    public void testGetConnection(){
        try {
            CONNECTION = getDBConnection();
        } catch (SQLException e) {
            System.out.println("Error in DB connection");
        }

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String vendor = introspector.getJDBCVendor();
        Assert.assertEquals("Incorrect DB vendor", JDBCVendor.HSQLDB, vendor);
    }

    @Test
    public void testGetConnection1(){
        try {
            CONNECTION = getDBConnection1();
        } catch (SQLException e) {
            System.out.println("Error in DB connection");
        }

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String vendor = introspector.getJDBCVendor();
        Assert.assertEquals("Incorrect DB vendor", JDBCVendor.HSQLDB, vendor);
    }
}
