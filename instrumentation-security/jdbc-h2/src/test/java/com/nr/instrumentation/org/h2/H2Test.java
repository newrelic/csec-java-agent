package com.nr.instrumentation.org.h2;

import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.api.agent.Trace;
import com.newrelic.api.agent.security.schema.JDBCVendor;
import org.h2.jdbc.JdbcConnection;
import org.junit.Assert;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.Properties;

/**
 * This is a quick test to allow make sure the unit test framework works with the module testrunner.
 */
@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = { "org.h2", "java.sql" })
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class H2Test {
    private static final String DB_DRIVER = "org.h2.Driver";
    private static final String DB_CONNECTION = "jdbc:h2:mem:test;DB_CLOSE_DELAY=-1";
    private static final String DB_USER = "";
    private static final String DB_PASSWORD = "";

    @Test
    public void testConnect() throws SQLException {
        getConnection();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String vendor = introspector.getJDBCVendor();
        Assert.assertEquals("Incorrect DB vendor", vendor, JDBCVendor.H2);

    }

    @Test
    public void testConnect1() throws SQLException {
        getConnection1();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String vendor = introspector.getJDBCVendor();
        Assert.assertEquals("Incorrect DB vendor", vendor, JDBCVendor.H2);

    }

    @Test
    public void testConnect2() throws SQLException {
        getConnection2();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String vendor = introspector.getJDBCVendor();
        Assert.assertEquals("Incorrect DB vendor", vendor, JDBCVendor.H2);

    }

    @Trace(dispatcher = true)
    private void getConnection() throws SQLException {
        Connection c = null;
        try {
            Class.forName(DB_DRIVER);
            c = DriverManager.getConnection(DB_CONNECTION, DB_USER, DB_PASSWORD);
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
            Class.forName(DB_DRIVER);
            Properties info = new Properties();
            info.put("user", DB_USER);
            info.put("password", DB_PASSWORD);
            c= new JdbcConnection(DB_CONNECTION, info);
            c = DriverManager.getConnection(DB_CONNECTION, info);
        } catch (Exception e) {
            System.out.println("Error in DB connection: " + e);
        } finally {
            if (c != null) {
                c.close();
            }
        }
    }

    @Trace(dispatcher = true)
    private void getConnection2() throws SQLException {
        Connection c = null;
        try {
            Class.forName(DB_DRIVER);
            Properties info = new Properties();
            info.put("user", DB_USER);
            info.put("password", DB_PASSWORD);
            c = new JdbcConnection(DB_CONNECTION, info);
        } catch (Exception e) {
            System.out.println("Error in DB connection: " + e);
        } finally {
            if (c != null) {
                c.close();
            }
        }
    }
}