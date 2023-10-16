/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */
package com.nr.agent.security.instrumentation.jdbc.mysql8011;

import com.mysql.cj.conf.HostInfo;
import com.mysql.cj.jdbc.ConnectionImpl;
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
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.Properties;
import java.util.concurrent.TimeUnit;

import static com.wix.mysql.EmbeddedMysql.anEmbeddedMysql;
import static com.wix.mysql.ScriptResolver.classPathScript;
import static com.wix.mysql.config.Charset.UTF8;
import static com.wix.mysql.config.MysqldConfig.aMysqldConfig;
import static com.wix.mysql.distribution.Version.v5_7_latest;

@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = {"com.mysql.cj"})
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class MySql8011DriverTest {
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
    public static void tearDownDb() {
        if (mysqld!=null) {
            mysqld.stop();
        }
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

    @Test
    public void testConnect3() throws SQLException {
        getConnection3();

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
        } catch (Exception ignored) {
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
        } catch (Exception ignored) {
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
        } catch (Exception ignored) {
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
            Class.forName("com.mysql.cj.jdbc.Driver");
            int port = mysqld.getConfig().getPort();
            String host = "localhost";
            dbConnection = ConnectionImpl.getInstance(new HostInfo(
                    () -> DB_CONNECTION, host, port, DB_USER, DB_PASSWORD
            ));
        } catch (Exception ignored) {
        }
        finally {
            if (dbConnection!=null) {
                dbConnection.close();
            }
        }
    }
}
