/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

import ch.vorburger.mariadb4j.DB;
import ch.vorburger.mariadb4j.DBConfigurationBuilder;
import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
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
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = {"com.mysql.cj.api.jdbc"})
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class MySqlConnection602Test {

    private static DB mariaDb;

    private static String connectionString;
    private static String dbName;

    private static com.mysql.cj.api.jdbc.JdbcConnection connection;

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

        Class.forName("com.mysql.cj.jdbc.Driver");
        connection = (com.mysql.cj.api.jdbc.JdbcConnection) DriverManager.getConnection(connectionString, "root", "");
    }

    @AfterClass
    public static void tearDownDb() throws Exception {
        mariaDb.stop();
    }

    @Test
    public void testClientPrepareStatement() throws SQLException {
        PreparedStatement statement = connection.clientPrepareStatement(QUERIES.get(0));

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String query = introspector.getSqlQuery((Statement) statement);

        Assert.assertEquals("Incorrect SQL query.", QUERIES.get(0), query);
    }

    @Test
    public void testClientPrepareStatement1() throws SQLException {
        PreparedStatement statement = connection.clientPrepareStatement(QUERIES.get(0), 1);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String query = introspector.getSqlQuery((Statement) statement);

        Assert.assertEquals("Incorrect SQL query.", QUERIES.get(0), query);
    }

    @Test
    public void testClientPrepareStatement2() throws SQLException {
        PreparedStatement statement = connection.clientPrepareStatement(QUERIES.get(0), 1, ResultSet.TYPE_SCROLL_INSENSITIVE);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String query = introspector.getSqlQuery((Statement) statement);

        Assert.assertEquals("Incorrect SQL query.", QUERIES.get(0), query);
    }

    @Test
    public void testClientPrepareStatement3() throws SQLException {
        PreparedStatement statement = connection.clientPrepareStatement(QUERIES.get(0), new int[] { 1, 2 });

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String query = introspector.getSqlQuery((Statement) statement);

        Assert.assertEquals("Incorrect SQL query.", QUERIES.get(0), query);
    }

    @Test
    public void testClientPrepareStatement4() throws SQLException {
        PreparedStatement statement = connection.clientPrepareStatement(QUERIES.get(0), 1, ResultSet.TYPE_SCROLL_INSENSITIVE, ResultSet.CLOSE_CURSORS_AT_COMMIT);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String query = introspector.getSqlQuery((Statement) statement);

        Assert.assertEquals("Incorrect SQL query.", QUERIES.get(0), query);
    }

    @Test
    public void testClientPrepareStatement5() throws SQLException {
        PreparedStatement statement = connection.clientPrepareStatement(QUERIES.get(0), new String[] { "value" });

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String query = introspector.getSqlQuery((Statement) statement);

        Assert.assertEquals("Incorrect SQL query.", QUERIES.get(0), query);
    }

    @Test
    public void testServerPrepareStatement() throws SQLException {
        PreparedStatement statement = connection.serverPrepareStatement(QUERIES.get(0));

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String query = introspector.getSqlQuery((Statement) statement);

        Assert.assertEquals("Incorrect SQL query.", QUERIES.get(0), query);
    }

    @Test
    public void testServerPrepareStatement1() throws SQLException {
        PreparedStatement statement = connection.serverPrepareStatement(QUERIES.get(0), 1);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String query = introspector.getSqlQuery((Statement) statement);

        Assert.assertEquals("Incorrect SQL query.", QUERIES.get(0), query);
    }

    @Test
    public void testServerPrepareStatement2() throws SQLException {
        PreparedStatement statement = connection.serverPrepareStatement(QUERIES.get(0), 1, ResultSet.TYPE_SCROLL_SENSITIVE);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String query = introspector.getSqlQuery((Statement) statement);

        Assert.assertEquals("Incorrect SQL query.", QUERIES.get(0), query);
    }

    @Test
    public void testServerPrepareStatement3() throws SQLException {
        PreparedStatement statement = connection.serverPrepareStatement(QUERIES.get(0), 1, ResultSet.TYPE_SCROLL_SENSITIVE, ResultSet.HOLD_CURSORS_OVER_COMMIT);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String query = introspector.getSqlQuery((Statement) statement);

        Assert.assertEquals("Incorrect SQL query.", QUERIES.get(0), query);
    }

    @Test
    public void testServerPrepareStatement4() throws SQLException {
        PreparedStatement statement = connection.serverPrepareStatement(QUERIES.get(0), new int[] { 1, 2 });

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String query = introspector.getSqlQuery((Statement) statement);

        Assert.assertEquals("Incorrect SQL query.", QUERIES.get(0), query);
    }

    @Test
    public void testServerPrepareStatement5() throws SQLException {
        PreparedStatement statement = connection.serverPrepareStatement(QUERIES.get(0), new String[] { "id" });

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String query = introspector.getSqlQuery((Statement) statement);

        Assert.assertEquals("Incorrect SQL query.", QUERIES.get(0), query);
    }
}
