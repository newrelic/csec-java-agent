/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */
package com.nr.instrumentation.security.mysql602;

import ch.vorburger.mariadb4j.DB;
import ch.vorburger.mariadb4j.DBConfigurationBuilder;
import com.mysql.cj.fabric.jdbc.FabricMySQLDataSource;
import com.mysql.cj.jdbc.MysqlConnectionPoolDataSource;
import com.mysql.cj.jdbc.MysqlDataSource;
import com.mysql.cj.jdbc.MysqlXADataSource;
import com.newrelic.agent.deps.org.jetbrains.annotations.NotNull;
import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.api.agent.Trace;
import com.newrelic.api.agent.security.schema.JDBCVendor;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;

import java.sql.Connection;
import java.sql.SQLException;

@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = {"com.mysql.cj"})
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class MySql602DataStoreTest {
    private static final String DB_USER = "";
    private static final String DB_PASSWORD = "";
    private static String DB_CONNECTION;
    private static String DB_NAME;
    private static DB mariaDb;

    @BeforeClass
    public static void setUpDb() throws Exception {
        DBConfigurationBuilder builder = DBConfigurationBuilder.newBuilder()
                .setPort(0); // This will automatically find a free port

        DB_NAME = "MariaDB" + System.currentTimeMillis();
        mariaDb = DB.newEmbeddedDB(builder.build());
        DB_CONNECTION = builder.getURL(DB_NAME) + "?useSSL=false";
        mariaDb.start();

        mariaDb.createDB(DB_NAME);
        mariaDb.source("maria-db-test.sql", null, null, DB_NAME);
    }

    @AfterClass
    public static void tearDownDb() throws Exception {
        mariaDb.stop();
    }

    @Test
    public void testGetConnectionMysqlDataSource() {
        try {
            callGetConnectionMysqlDataSource();
        } catch (Exception e) {
            System.out.println("Error in DB connection");
        }

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String vendor = introspector.getJDBCVendor();
        Assert.assertEquals("Incorrect DB vendor", JDBCVendor.MYSQL, vendor);
    }

    @Test
    public void testGetConnectionMysqlDataSource1() {
        try {
            callGetConnectionMysqlDataSource1();
        } catch (Exception e) {
            System.out.println("Error in DB connection");
        }

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String vendor = introspector.getJDBCVendor();
        Assert.assertEquals("Incorrect DB vendor", JDBCVendor.MYSQL, vendor);
    }

    @Test
    public void testGetConnectionFabricMySQLDataSource() {
        try {
            callGetConnectionFabricMySQLDataSource();
        } catch (Exception e) {
            System.out.println("Error in DB connection");
        }

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String vendor = introspector.getJDBCVendor();
        Assert.assertEquals("Incorrect DB vendor", JDBCVendor.MYSQL, vendor);
    }

    @Test
    public void testGetConnectionFabricMySQLDataSource1() {
        try {
            callGetConnectionFabricMySQLDataSource1();
        } catch (Exception e) {
            System.out.println("Error in DB connection");
        }

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String vendor = introspector.getJDBCVendor();
        Assert.assertEquals("Incorrect DB vendor", JDBCVendor.MYSQL, vendor);
    }

    @Test
    public void testGetConnectionMysqlConnectionPoolDataSource() {
        try {
            callGetConnectionMysqlConnectionPoolDataSource();
        } catch (Exception e) {
            System.out.println("Error in DB connection");
        }

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String vendor = introspector.getJDBCVendor();
        Assert.assertEquals("Incorrect DB vendor", JDBCVendor.MYSQL, vendor);
    }

    @Test
    public void testGetConnectionMysqlConnectionPoolDataSource1() {
        try {
            callGetConnectionMysqlConnectionPoolDataSource1();
        } catch (Exception e) {
            System.out.println("Error in DB connection");
        }

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String vendor = introspector.getJDBCVendor();
        Assert.assertEquals("Incorrect DB vendor", JDBCVendor.MYSQL, vendor);
    }

    @Test
    public void testGetConnectionMysqlXADataSource() {
        try {
            callGetConnectionMysqlXADataSource();
        } catch (Exception e) {
            System.out.println("Error in DB connection");
        }

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String vendor = introspector.getJDBCVendor();
        Assert.assertEquals("Incorrect DB vendor", JDBCVendor.MYSQL, vendor);
    }

    @Test
    public void testGetConnectionMysqlXADataSource1() {
        try {
            callGetConnectionMysqlXADataSource1();
        } catch (Exception e) {
            System.out.println("Error in DB connection");
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

    private void getConnection(@NotNull MysqlDataSource baseDataSource) throws SQLException {
        baseDataSource.setURL(DB_CONNECTION);
        baseDataSource.setDatabaseName(DB_NAME);
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

    private void getConnection1(@NotNull MysqlDataSource baseDataSource) throws SQLException {
        baseDataSource.setURL(DB_CONNECTION);
        baseDataSource.setDatabaseName(DB_NAME);
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
