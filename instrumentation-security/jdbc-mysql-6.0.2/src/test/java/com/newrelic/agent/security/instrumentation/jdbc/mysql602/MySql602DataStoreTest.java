/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */
package com.newrelic.agent.security.instrumentation.jdbc.mysql602;

import com.mysql.cj.fabric.jdbc.FabricMySQLDataSource;
import com.mysql.cj.jdbc.MysqlConnectionPoolDataSource;
import com.mysql.cj.jdbc.MysqlDataSource;
import com.mysql.cj.jdbc.MysqlXADataSource;
import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.api.agent.Trace;
import com.newrelic.api.agent.security.schema.JDBCVendor;
import com.wix.mysql.EmbeddedMysql;
import com.wix.mysql.config.MysqldConfig;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;

import java.sql.Connection;
import java.sql.SQLException;
import java.util.concurrent.TimeUnit;

import static com.wix.mysql.EmbeddedMysql.anEmbeddedMysql;
import static com.wix.mysql.ScriptResolver.classPathScript;
import static com.wix.mysql.config.Charset.UTF8;
import static com.wix.mysql.config.MysqldConfig.aMysqldConfig;
import static com.wix.mysql.distribution.Version.v5_7_latest;

@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = {"com.mysql.cj"})
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class MySql602DataStoreTest {
    private static final String DB_USER = "";
    private static final String DB_PASSWORD = "";
    private static String DB_CONNECTION;
    private static String DB_NAME = "test";
    private static EmbeddedMysql mysqld = null;

    @BeforeClass
    public static void setUpDb() throws Exception {
        MysqldConfig config = aMysqldConfig(v5_7_latest)
                .withCharset(UTF8)
                .withFreePort()
                .withTimeout(2, TimeUnit.MINUTES)
                .withUser(DB_USER, DB_PASSWORD)
                .build();

        mysqld = anEmbeddedMysql(config)
                .addSchema(DB_NAME, classPathScript("maria-db-test.sql"))
                .start();

        DB_CONNECTION = "jdbc:mysql://localhost:" + mysqld.getConfig().getPort() + "/" + DB_NAME + "?useSSL=false";
    }

    @AfterClass
    public static void tearDownDb() throws Exception {
        if (mysqld!=null) {
            mysqld.stop();
        }
    }

    @Test
    public void testGetConnectionMysqlDataSource() {
        try {
            callGetConnectionMysqlDataSource();
        } catch (Exception ignored) {
        }

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String vendor = introspector.getJDBCVendor();
        Assert.assertEquals("Incorrect DB vendor", JDBCVendor.MYSQL, vendor);
    }

    @Test
    public void testGetConnectionMysqlDataSource1() {
        try {
            callGetConnectionMysqlDataSource1();
        } catch (Exception ignored) {
        }

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String vendor = introspector.getJDBCVendor();
        Assert.assertEquals("Incorrect DB vendor", JDBCVendor.MYSQL, vendor);
    }

    @Test
    public void testGetConnectionFabricMySQLDataSource() {
        try {
            callGetConnectionFabricMySQLDataSource();
        } catch (Exception ignored) {
        }

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String vendor = introspector.getJDBCVendor();
        Assert.assertEquals("Incorrect DB vendor", JDBCVendor.MYSQL, vendor);
    }

    @Test
    public void testGetConnectionFabricMySQLDataSource1() {
        try {
            callGetConnectionFabricMySQLDataSource1();
        } catch (Exception ignored) {
        }

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String vendor = introspector.getJDBCVendor();
        Assert.assertEquals("Incorrect DB vendor", JDBCVendor.MYSQL, vendor);
    }

    @Test
    public void testGetConnectionMysqlConnectionPoolDataSource() {
        try {
            callGetConnectionMysqlConnectionPoolDataSource();
        } catch (Exception ignored) {
        }

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String vendor = introspector.getJDBCVendor();
        Assert.assertEquals("Incorrect DB vendor", JDBCVendor.MYSQL, vendor);
    }

    @Test
    public void testGetConnectionMysqlConnectionPoolDataSource1() {
        try {
            callGetConnectionMysqlConnectionPoolDataSource1();
        } catch (Exception ignored) {
        }

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String vendor = introspector.getJDBCVendor();
        Assert.assertEquals("Incorrect DB vendor", JDBCVendor.MYSQL, vendor);
    }

    @Test
    public void testGetConnectionMysqlXADataSource() {
        try {
            callGetConnectionMysqlXADataSource();
        } catch (Exception ignored) {
        }

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String vendor = introspector.getJDBCVendor();
        Assert.assertEquals("Incorrect DB vendor", JDBCVendor.MYSQL, vendor);
    }

    @Test
    public void testGetConnectionMysqlXADataSource1() {
        try {
            callGetConnectionMysqlXADataSource1();
        } catch (Exception ignored) {
        }

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String vendor = introspector.getJDBCVendor();
        Assert.assertEquals("Incorrect DB vendor", JDBCVendor.MYSQL, vendor);
    }

    @Trace(dispatcher = true)
    private void callGetConnectionMysqlDataSource() throws SQLException {
        getConnection(new MysqlDataSource());
    }

    @Trace(dispatcher = true)
    private void callGetConnectionMysqlDataSource1() throws SQLException {
        getConnection1(new MysqlDataSource());
    }

    @Trace(dispatcher = true)
    private void callGetConnectionFabricMySQLDataSource() throws SQLException {
        getConnection(new FabricMySQLDataSource());
    }

    @Trace(dispatcher = true)
    private void callGetConnectionFabricMySQLDataSource1() throws SQLException {
        getConnection1(new FabricMySQLDataSource());
    }

    @Trace(dispatcher = true)
    private void callGetConnectionMysqlConnectionPoolDataSource() throws SQLException {
        getConnection(new MysqlConnectionPoolDataSource());
    }

    @Trace(dispatcher = true)
    private void callGetConnectionMysqlConnectionPoolDataSource1() throws SQLException {
        getConnection1(new MysqlConnectionPoolDataSource());
    }

    @Trace(dispatcher = true)
    private void callGetConnectionMysqlXADataSource() throws SQLException {
        getConnection(new MysqlXADataSource());
    }

    @Trace(dispatcher = true)
    private void callGetConnectionMysqlXADataSource1() throws SQLException {
        getConnection1(new MysqlXADataSource());
    }

    private void getConnection(MysqlDataSource baseDataSource) throws SQLException {
        baseDataSource.setURL(DB_CONNECTION);
        baseDataSource.setDatabaseName(DB_NAME);
        Connection conn = null;

        try {
            conn = baseDataSource.getConnection(DB_USER, DB_PASSWORD);
        } catch (Exception ignored) {
        } finally {
            if (conn!=null) {
                conn.close();
            }
        }
    }

    private void getConnection1(MysqlDataSource baseDataSource) throws SQLException {
        baseDataSource.setURL(DB_CONNECTION);
        baseDataSource.setDatabaseName(DB_NAME);
        baseDataSource.setUser(DB_USER);
        baseDataSource.setPassword(DB_PASSWORD);
        Connection conn = null;

        try {
            conn = baseDataSource.getConnection();
        } catch (Exception ignored) {
        } finally {
            if (conn!=null) {
                conn.close();
            }
        }
    }
}
