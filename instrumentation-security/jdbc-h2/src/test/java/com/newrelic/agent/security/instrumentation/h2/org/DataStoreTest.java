package com.newrelic.agent.security.instrumentation.h2.org;

import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.api.agent.Trace;
import com.newrelic.api.agent.security.schema.JDBCVendor;
import org.h2.jdbcx.JdbcDataSource;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.sql.Connection;
import java.sql.SQLException;

@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = { "javax.sql", "java.sql", "org.h2" })
public class DataStoreTest {
    private static final String DB_CONNECTION = "jdbc:h2:mem:test;DB_CLOSE_DELAY=-1";
    private static final String DB_USER = "";
    private static final String DB_PASSWORD = "";

    @Test
    public void testGetConnectionJdbcDataSource() throws SQLException {
        callGetConnectionJdbcDataSource();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String vendor = introspector.getJDBCVendor();
        Assert.assertEquals("Incorrect DB vendor", JDBCVendor.H2, vendor);
    }

    @Test
    public void testGetConnectionJdbcDataSource1() throws SQLException {
        callGetConnectionJdbcDataSource1();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String vendor = introspector.getJDBCVendor();
        Assert.assertEquals("Incorrect DB vendor", JDBCVendor.H2, vendor);
    }

    @Trace(dispatcher = true)
    private void callGetConnectionJdbcDataSource() throws SQLException {
        getConnection(new JdbcDataSource());
    }

    @Trace(dispatcher = true)
    private void callGetConnectionJdbcDataSource1() throws SQLException {
        getConnection1(new JdbcDataSource());
    }

    private void getConnection(JdbcDataSource baseDataSource) throws SQLException {
        Connection conn = null;
        baseDataSource.setURL(DB_CONNECTION);

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

    private void getConnection1(JdbcDataSource baseDataSource) throws SQLException {
        baseDataSource.setURL(DB_CONNECTION);
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
