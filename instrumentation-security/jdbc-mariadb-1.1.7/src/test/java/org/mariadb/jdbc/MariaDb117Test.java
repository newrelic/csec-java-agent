/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package org.mariadb.jdbc;

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
import org.mariadb.jdbc.internal.common.QueryException;
import org.mariadb.jdbc.internal.mysql.MySQLProtocol;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = {"org.mariadb.jdbc"})
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class MariaDb117Test {
    private static DB mariaDb;
    private static String connectionString;
    private static String dbName;
    private static final String DB_USER = "";
    private static final String DB_PASSWORD = "";
    private static List<String> QUERIES = new ArrayList<>();

    @BeforeClass
    public static void setUpDb() throws Exception {
        QUERIES.add("select * from testQuery");
        DBConfigurationBuilder builder = DBConfigurationBuilder.newBuilder()
                .setPort(0); // This will automatically find a free port

        dbName = "MariaDB" + System.currentTimeMillis();
        mariaDb = DB.newEmbeddedDB(builder.build());
        connectionString = builder.getURL(dbName);
        mariaDb.start();

        mariaDb.createDB(dbName);
        mariaDb.source("maria-db-test.sql", null, null, dbName);
    }
    @AfterClass
    public static void tearDownDb() throws Exception {
        mariaDb.stop();
    }

    @Test
    public void testConnect() throws SQLException, ClassNotFoundException {
        getConnection();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String vendor = introspector.getJDBCVendor();
        Assert.assertEquals("Incorrect DB vendor", JDBCVendor.MARIA_DB, vendor);
    }

    @Test
    public void testConnect1() throws SQLException, ClassNotFoundException {
        getConnection1();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String vendor = introspector.getJDBCVendor();
        Assert.assertEquals("Incorrect DB vendor", JDBCVendor.MARIA_DB, vendor);
    }

    @Test
    public void testConnect2() throws SQLException, ClassNotFoundException {
        getConnection2();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String vendor = introspector.getJDBCVendor();
        Assert.assertEquals("Incorrect DB vendor", JDBCVendor.MARIA_DB, vendor);
    }

    @Test
    public void testConnect3() throws SQLException, ClassNotFoundException, QueryException {
        getConnection3();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String vendor = introspector.getJDBCVendor();
        Assert.assertEquals("Incorrect DB vendor", JDBCVendor.MARIA_DB, vendor);
    }

    @Trace(dispatcher = true)
    private void getConnection() throws SQLException {
        Connection dbConnection = null;

        try {
            Class.forName("org.mariadb.jdbc.Driver");
            dbConnection = DriverManager.getConnection(connectionString, DB_USER, DB_PASSWORD);
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
            Class.forName("org.mariadb.jdbc.Driver");
            dbConnection = DriverManager.getConnection(connectionString, info);
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
            Class.forName("org.mariadb.jdbc.Driver");
            dbConnection = DriverManager.getConnection(connectionString);
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
    private void getConnection3() throws SQLException {
        Connection dbConnection = null;

        try {
            Class.forName("org.mariadb.jdbc.Driver");
            dbConnection = MySQLConnection.newConnection(new MySQLProtocol(JDBCUrl.parse(connectionString), "", "", new Properties()));
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
