package com.nr.instrumentation.security.derby10216;

import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.api.agent.Trace;
import com.newrelic.api.agent.security.schema.JDBCVendor;
import org.apache.derby.jdbc.EmbeddedConnectionPoolDataSource;
import org.apache.derby.jdbc.EmbeddedConnectionPoolDataSource40;
import org.apache.derby.jdbc.EmbeddedDataSource;
import org.apache.derby.jdbc.EmbeddedDataSource40;
import org.apache.derby.jdbc.EmbeddedXADataSource40;
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
@InstrumentationTestConfig(includePrefixes = "org.apache.derby.jdbc")
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class DerbyDataStoreTest {
    private static final String DB_NAME = "test";
    private static final String DB_USER = "";
    private static final String DB_PASSWORD = "";

    @Test
    public void testGetConnectionEmbeddedDataSource() {
        try {
            callGetConnectionEmbeddedDataSource();
        } catch (Exception e) {
        }

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String vendor = introspector.getJDBCVendor();
        Assert.assertEquals("Incorrect DB vendor", JDBCVendor.DERBY, vendor);
    }

    @Test
    public void testGetConnectionEmbeddedDataSource1() {
        try {
            callGetConnectionEmbeddedDataSource1();
        } catch (Exception e) {

        }

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String vendor = introspector.getJDBCVendor();
        Assert.assertEquals("Incorrect DB vendor", JDBCVendor.DERBY, vendor);
    }

    @Test
    public void testGetConnectionEmbeddedDataSource40() {
        try {
            callGetConnectionEmbeddedDataSource40();
        } catch (Exception e) {

        }

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String vendor = introspector.getJDBCVendor();
        Assert.assertEquals("Incorrect DB vendor", JDBCVendor.DERBY, vendor);
    }

    @Test
    public void testGetConnectionEmbeddedDataSource401() {
        try {
            callGetConnectionEmbeddedDataSource401();
        } catch (Exception e) {

        }

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String vendor = introspector.getJDBCVendor();
        Assert.assertEquals("Incorrect DB vendor", JDBCVendor.DERBY, vendor);
    }

    @Test
    public void testGetConnectionEmbeddedXADataSource40() {
        try {
            callGetConnectionEmbeddedXADataSource40();
        } catch (Exception e) {

        }

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String vendor = introspector.getJDBCVendor();
        Assert.assertEquals("Incorrect DB vendor", JDBCVendor.DERBY, vendor);
    }

    @Test
    public void testGetConnectionEmbeddedXADataSource401() {
        try {
            callGetConnectionEmbeddedXADataSource401();
        } catch (Exception e) {

        }

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String vendor = introspector.getJDBCVendor();
        Assert.assertEquals("Incorrect DB vendor", JDBCVendor.DERBY, vendor);
    }

    @Test
    public void testGetConnectionEmbeddedConnectionPoolDataSource() {
        try {
            callGetConnectionEmbeddedConnectionPoolDataSource();
        } catch (Exception e) {

        }

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String vendor = introspector.getJDBCVendor();
        Assert.assertEquals("Incorrect DB vendor", JDBCVendor.DERBY, vendor);
    }

    @Test
    public void testGetConnectionEmbeddedConnectionPoolDataSource1() {
        try {
            callGetConnectionEmbeddedConnectionPoolDataSource1();
        } catch (Exception e) {

        }

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String vendor = introspector.getJDBCVendor();
        Assert.assertEquals("Incorrect DB vendor", JDBCVendor.DERBY, vendor);
    }

    @Test
    public void testGetConnectionEmbeddedConnectionPoolDataSource40() {
        try {
            callGetConnectionEmbeddedConnectionPoolDataSource40();
        } catch (Exception e) {

        }

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String vendor = introspector.getJDBCVendor();
        Assert.assertEquals("Incorrect DB vendor", JDBCVendor.DERBY, vendor);
    }

    @Test
    public void testGetConnectionEmbeddedConnectionPoolDataSource401() {
        try {
            callGetConnectionEmbeddedConnectionPoolDataSource401();
        } catch (Exception e) {

        }

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String vendor = introspector.getJDBCVendor();
        Assert.assertEquals("Incorrect DB vendor", JDBCVendor.DERBY, vendor);
    }

    @Trace(dispatcher = true)
    private void callGetConnectionEmbeddedDataSource() throws SQLException {
        getConnection(new EmbeddedDataSource());
    }

    @Trace(dispatcher = true)
    private void callGetConnectionEmbeddedDataSource1() throws SQLException {
        getConnection1(new EmbeddedDataSource());
    }

    @Trace(dispatcher = true)
    private void callGetConnectionEmbeddedDataSource40() throws SQLException {
        getConnection(new EmbeddedDataSource40());
    }

    @Trace(dispatcher = true)
    private void callGetConnectionEmbeddedDataSource401() throws SQLException {
        getConnection1(new EmbeddedDataSource40());
    }

    @Trace(dispatcher = true)
    private void callGetConnectionEmbeddedXADataSource40() throws SQLException {
        getConnection(new EmbeddedXADataSource40());
    }

    @Trace(dispatcher = true)
    private void callGetConnectionEmbeddedXADataSource401() throws SQLException {
        getConnection1(new EmbeddedXADataSource40());
    }

    @Trace(dispatcher = true)
    private void callGetConnectionEmbeddedConnectionPoolDataSource() throws SQLException {
        getConnection(new EmbeddedConnectionPoolDataSource());
    }

    @Trace(dispatcher = true)
    private void callGetConnectionEmbeddedConnectionPoolDataSource1() throws SQLException {
        getConnection1(new EmbeddedConnectionPoolDataSource());
    }

    @Trace(dispatcher = true)
    private void callGetConnectionEmbeddedConnectionPoolDataSource40() throws SQLException {
        getConnection(new EmbeddedConnectionPoolDataSource40());
    }

    @Trace(dispatcher = true)
    private void callGetConnectionEmbeddedConnectionPoolDataSource401() throws SQLException {
        getConnection1(new EmbeddedConnectionPoolDataSource40());
    }

    private void getConnection(EmbeddedDataSource baseDataSource) throws SQLException {
        baseDataSource.setCreateDatabase("create");
        baseDataSource.setDatabaseName(DB_NAME);
        Connection conn = null;

        try {
            conn = baseDataSource.getConnection(DB_USER, DB_PASSWORD);
        } catch (Exception e) {

        } finally {
            if (conn!=null) {
                conn.close();
            }
        }
    }

    private void getConnection1(EmbeddedDataSource baseDataSource) throws SQLException {
        baseDataSource.setCreateDatabase("create");
        baseDataSource.setDatabaseName(DB_NAME);
        baseDataSource.setUser(DB_USER);
        baseDataSource.setPassword(DB_PASSWORD);
        Connection conn = null;

        try {
            conn = baseDataSource.getConnection();
        } catch (Exception e) {

        } finally {
            if (conn!=null) {
                conn.close();
            }
        }
    }
}
