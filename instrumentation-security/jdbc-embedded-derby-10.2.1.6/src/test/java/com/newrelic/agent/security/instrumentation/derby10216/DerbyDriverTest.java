package com.newrelic.agent.security.instrumentation.derby10216;

import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.api.agent.Trace;
import com.newrelic.api.agent.security.schema.JDBCVendor;
import org.apache.derby.jdbc.AutoloadedDriver;
import org.apache.derby.jdbc.EmbeddedDriver;
import org.junit.Assert;
import org.junit.Before;
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
@InstrumentationTestConfig(includePrefixes = "org.apache.derby.jdbc")
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class DerbyDriverTest {
    private static final String DB_DRIVER = "org.apache.derby.jdbc.EmbeddedDriver";
    private static final String DB_CONNECTION = "jdbc:derby:memory:test;create=true;DB_CLOSE_DELAY=-1";
    private static final String DB_USER = "";
    private static final String DB_PASSWORD = "";

    @Before
    public void init() throws SQLException {
        // registering Autoloaded driver so that it can be deregistered by the Helper
        // and then the Embedded driver can be registered and used
        DriverManager.registerDriver(new AutoloadedDriver());
        Helper.setup(DB_CONNECTION);
    }

    @Test
    public void testConnect() throws SQLException {
        getConnection();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String vendor = introspector.getJDBCVendor();
        Assert.assertEquals("Incorrect DB vendor", JDBCVendor.DERBY, vendor);

    }

    @Test
    public void testConnect1() throws SQLException {
        getConnection1();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String vendor = introspector.getJDBCVendor();
        Assert.assertEquals("Incorrect DB vendor", JDBCVendor.DERBY, vendor);

    }

    @Test
    public void testConnect2() throws SQLException {
        getConnection2();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String vendor = introspector.getJDBCVendor();
        Assert.assertEquals("Incorrect DB vendor", JDBCVendor.DERBY, vendor);

    }

    @Trace(dispatcher = true)
    private void getConnection() throws SQLException {
        Connection dbConnection = null;

        try {
            DriverManager.registerDriver(new EmbeddedDriver());
            dbConnection = DriverManager.getConnection(DB_CONNECTION, DB_USER, DB_PASSWORD);
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
            DriverManager.registerDriver(new EmbeddedDriver());
            dbConnection = DriverManager.getConnection(DB_CONNECTION, info);
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
            DriverManager.registerDriver(new EmbeddedDriver());
            dbConnection = DriverManager.getConnection(DB_CONNECTION);
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
