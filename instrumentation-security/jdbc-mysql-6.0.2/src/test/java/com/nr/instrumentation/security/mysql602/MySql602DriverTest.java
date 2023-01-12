/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */
package com.nr.instrumentation.security.mysql602;

import ch.vorburger.mariadb4j.DB;
import ch.vorburger.mariadb4j.DBConfigurationBuilder;
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
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.Properties;

@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = {"com.mysql.cj"})
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class MySql602DriverTest {
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
    public void testConnect() throws SQLException {
        getConnection();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String vendor = introspector.getJDBCVendor();
        Assert.assertEquals("Incorrect DB vendor", JDBCVendor.MYSQL, vendor);
    }

    @Test
    public void testConnect1() throws SQLException {
        getConnection1();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String vendor = introspector.getJDBCVendor();
        Assert.assertEquals("Incorrect DB vendor", JDBCVendor.MYSQL, vendor);
    }

    @Test
    public void testConnect2() throws SQLException {
        getConnection2();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String vendor = introspector.getJDBCVendor();
        Assert.assertEquals("Incorrect DB vendor", JDBCVendor.MYSQL, vendor);
    }

    @Trace(dispatcher = true)
    private void getConnection() throws SQLException {
        Connection dbConnection = null;

        try {
            Class.forName("com.mysql.cj.jdbc.Driver");
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
            Class.forName("com.mysql.cj.jdbc.Driver");
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
            Class.forName("com.mysql.cj.jdbc.Driver");
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
