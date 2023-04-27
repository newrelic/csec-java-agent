/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */
package com.nr.instrumentation.security.mysql604;

import com.mysql.cj.api.jdbc.JdbcConnection;
import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.wix.mysql.EmbeddedMysql;
import com.wix.mysql.config.MysqldConfig;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;

import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

import static com.wix.mysql.EmbeddedMysql.anEmbeddedMysql;
import static com.wix.mysql.ScriptResolver.classPathScript;
import static com.wix.mysql.config.Charset.UTF8;
import static com.wix.mysql.config.MysqldConfig.aMysqldConfig;
import static com.wix.mysql.distribution.Version.v5_7_latest;

@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = { "com.mysql.cj" })
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class MySql604Test {
    private static final String DB_USER = "";
    private static final String DB_PASSWORD = "";
    private static final List<String> QUERIES = new ArrayList<>();
    private static final String DB_NAME = "test";
    private static JdbcConnection connection;
    private static String DB_CONNECTION;
    private static EmbeddedMysql mysqld = null;

    @BeforeClass
    public static void setUpDb() throws Exception {
        QUERIES.add("select * from testQuery");
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
        Class.forName("com.mysql.cj.jdbc.Driver");
        connection = (JdbcConnection) DriverManager.getConnection(DB_CONNECTION, DB_USER, DB_PASSWORD);
    }

    @AfterClass
    public static void tearDownDb() throws Exception {
        if (mysqld != null) {
            mysqld.stop();
        }
    }

    @Test
    public void testClientPrepareStatement() throws SQLException {
        PreparedStatement statement = connection.clientPrepareStatement(QUERIES.get(0));

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String query = introspector.getSqlQuery(statement);

        Assert.assertEquals("Incorrect SQL query.", QUERIES.get(0), query);
    }

    @Test
    public void testClientPrepareStatement1() throws SQLException {
        PreparedStatement statement = connection.clientPrepareStatement(QUERIES.get(0), 1);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String query = introspector.getSqlQuery(statement);

        Assert.assertEquals("Incorrect SQL query.", QUERIES.get(0), query);
    }

    @Test
    public void testClientPrepareStatement2() throws SQLException {
        PreparedStatement statement = connection.clientPrepareStatement(QUERIES.get(0), 1, ResultSet.TYPE_SCROLL_INSENSITIVE);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String query = introspector.getSqlQuery(statement);

        Assert.assertEquals("Incorrect SQL query.", QUERIES.get(0), query);
    }

    @Test
    public void testClientPrepareStatement3() throws SQLException {
        PreparedStatement statement = connection.clientPrepareStatement(QUERIES.get(0), new int[] { 1, 2 });

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String query = introspector.getSqlQuery(statement);

        Assert.assertEquals("Incorrect SQL query.", QUERIES.get(0), query);
    }

    @Test
    public void testClientPrepareStatement4() throws SQLException {
        PreparedStatement statement = connection.clientPrepareStatement(QUERIES.get(0), 1, ResultSet.TYPE_SCROLL_INSENSITIVE,
                ResultSet.CLOSE_CURSORS_AT_COMMIT);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String query = introspector.getSqlQuery(statement);

        Assert.assertEquals("Incorrect SQL query.", QUERIES.get(0), query);
    }

    @Test
    public void testClientPrepareStatement5() throws SQLException {
        PreparedStatement statement = connection.clientPrepareStatement(QUERIES.get(0), new String[] { "value" });

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String query = introspector.getSqlQuery(statement);

        Assert.assertEquals("Incorrect SQL query.", QUERIES.get(0), query);
    }

    @Test
    public void testServerPrepareStatement() throws SQLException {
        PreparedStatement statement = connection.serverPrepareStatement(QUERIES.get(0));

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String query = introspector.getSqlQuery(statement);

        Assert.assertEquals("Incorrect SQL query.", QUERIES.get(0), query);
    }

    @Test
    public void testServerPrepareStatement1() throws SQLException {
        PreparedStatement statement = connection.serverPrepareStatement(QUERIES.get(0), 1);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String query = introspector.getSqlQuery(statement);

        Assert.assertEquals("Incorrect SQL query.", QUERIES.get(0), query);
    }

    @Test
    public void testServerPrepareStatement2() throws SQLException {
        PreparedStatement statement = connection.serverPrepareStatement(QUERIES.get(0), 1, ResultSet.TYPE_SCROLL_SENSITIVE);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String query = introspector.getSqlQuery(statement);

        Assert.assertEquals("Incorrect SQL query.", QUERIES.get(0), query);
    }

    @Test
    public void testServerPrepareStatement3() throws SQLException {
        PreparedStatement statement = connection.serverPrepareStatement(QUERIES.get(0), 1, ResultSet.TYPE_SCROLL_SENSITIVE, ResultSet.HOLD_CURSORS_OVER_COMMIT);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String query = introspector.getSqlQuery(statement);

        Assert.assertEquals("Incorrect SQL query.", QUERIES.get(0), query);
    }

    @Test
    public void testServerPrepareStatement4() throws SQLException {
        PreparedStatement statement = connection.serverPrepareStatement(QUERIES.get(0), new int[] { 1, 2 });

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String query = introspector.getSqlQuery(statement);

        Assert.assertEquals("Incorrect SQL query.", QUERIES.get(0), query);
    }

    @Test
    public void testServerPrepareStatement5() throws SQLException {
        PreparedStatement statement = connection.serverPrepareStatement(QUERIES.get(0), new String[] { "id" });

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String query = introspector.getSqlQuery(statement);

        Assert.assertEquals("Incorrect SQL query.", QUERIES.get(0), query);
    }
}
