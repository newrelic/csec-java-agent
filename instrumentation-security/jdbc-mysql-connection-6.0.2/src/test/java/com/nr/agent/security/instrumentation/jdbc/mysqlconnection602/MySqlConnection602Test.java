package com.nr.agent.security.instrumentation.jdbc.mysqlconnection602;

import com.mysql.cj.api.jdbc.JdbcConnection;
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
import org.testcontainers.containers.MySQLContainer;
import org.testcontainers.utility.DockerImageName;
import org.testcontainers.utility.MountableFile;

import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.TimeUnit;

@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = {"com.mysql.cj.api.jdbc"})
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class MySqlConnection602Test {

    private static final List<String> QUERIES = new ArrayList<>();

    private static JdbcConnection connection;

    private static String DB_CONNECTION;

    private static String DB_USER;

    private static String DB_PASSWORD;

    private static MySQLContainer<?> mysql;

    private static int PORT;

    @BeforeClass
    public static void setUpDb() throws ClassNotFoundException, SQLException {
        QUERIES.add("select * from testQuery");

        PORT = SecurityInstrumentationTestRunner.getIntrospector().getRandomPort();
        // System.setProperty("DOCKER_DEFAULT_PLATFORM", "linux/amd64");
        mysql = new MySQLContainer<>(DockerImageName.parse("mysql:5.7.43"))
                .withCopyFileToContainer(MountableFile.forClasspathResource("maria-db-test.sql"), "/docker-entrypoint-initdb.d/");
        mysql.setPortBindings(Collections.singletonList(PORT + ":3808"));
        mysql.start();

        DB_PASSWORD = mysql.getPassword();
        DB_USER = mysql.getUsername();
        DB_CONNECTION = mysql.getJdbcUrl()+"?useSSL=false";
        Class.forName("com.mysql.jdbc.Driver");
        connection = (JdbcConnection) DriverManager.getConnection(DB_CONNECTION, DB_USER, DB_PASSWORD);
    }

    @AfterClass
    public static void tearDownDb() {
        if (mysql != null && mysql.isCreated()) {
            mysql.close();
            mysql.stop();
        }
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
