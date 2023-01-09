package com.nr.instrumentation.security.postgresql941207;

import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.security.schema.operation.SQLOperation;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;
import org.testcontainers.containers.PostgreSQLContainer;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = "org.postgresql")
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class PgStatementTest {
    private static final String DB_USER = "postgres";
    private static final String DB_PASSWORD = "postgres";
    @ClassRule
    public static PostgreSQLContainer postgreSQLContainer = new PostgreSQLContainer("postgres:11.1")
            .withDatabaseName("test")
            .withUsername(DB_USER)
            .withPassword(DB_PASSWORD);
    private static Connection CONNECTION;
    private static List<String> QUERIES = new ArrayList<>();

    @AfterClass
    public static void cleanup() throws SQLException {
        CONNECTION.close();
    }

    public static void getConnection(){
        try {
            Class.forName("org.postgresql.Driver");
            CONNECTION = DriverManager.getConnection(postgreSQLContainer.getJdbcUrl(), DB_USER, DB_PASSWORD);
        } catch (Exception e) {
            System.out.println("Error in DB connection: "+e);
        }
    }

    @BeforeClass
    public static void initData() throws SQLException {
        getConnection();
        QUERIES.add("CREATE TABLE IF NOT EXISTS USERS(id int primary key, first_name varchar(255), last_name varchar(255))");
        QUERIES.add("TRUNCATE TABLE USERS");
        QUERIES.add("INSERT INTO USERS(id, first_name, last_name) VALUES(1, 'john', 'doe')");
        QUERIES.add("SELECT * FROM USERS");
        QUERIES.add("UPDATE USERS SET \"last_name\"='Doe' WHERE id=1");
        // set up data in h2
        Statement stmt = CONNECTION.createStatement();
        stmt.execute(QUERIES.get(0));
        stmt.execute(QUERIES.get(1));
        stmt.execute(QUERIES.get(2));
        stmt.close();
    }

    @Test
    public void testExecute() throws SQLException {
        Statement stmt = CONNECTION.createStatement();
        stmt.execute(QUERIES.get(3));

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        SQLOperation operation = (SQLOperation) operations.get(0);
        Assert.assertEquals("Invalid executed parameters.", QUERIES.get(3), operation.getQuery());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.SQL_DB_COMMAND, operation.getCaseType());
    }

    @Test
    public void testExecute1() throws SQLException {
        PreparedStatement stmt = CONNECTION.prepareStatement(QUERIES.get(3));
        stmt.execute();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        SQLOperation operation = (SQLOperation) operations.get(0);
        Assert.assertEquals("Invalid executed parameters.", QUERIES.get(3), operation.getQuery());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.SQL_DB_COMMAND, operation.getCaseType());
    }

    @Test
    public void testExecuteQuery() throws SQLException {
        Statement stmt = CONNECTION.createStatement();
        stmt.executeQuery(QUERIES.get(3));

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        SQLOperation operation = (SQLOperation) operations.get(0);
        Assert.assertEquals("Invalid executed parameters.", QUERIES.get(3),operation.getQuery());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.SQL_DB_COMMAND, operation.getCaseType());
    }

    @Test
    public void testExecuteQuery1() throws SQLException {
        PreparedStatement stmt = CONNECTION.prepareStatement(QUERIES.get(3));
        stmt.executeQuery();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        SQLOperation operation = (SQLOperation) operations.get(0);
        Assert.assertEquals("Invalid executed parameters.", QUERIES.get(3),operation.getQuery());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.SQL_DB_COMMAND, operation.getCaseType());
    }

    @Test
    public void testExecuteUpdate() throws SQLException {
        Statement stmt = CONNECTION.createStatement();
        stmt.executeUpdate(QUERIES.get(4));

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        SQLOperation operation = (SQLOperation) operations.get(0);
        Assert.assertEquals("Invalid executed parameters.", QUERIES.get(4),operation.getQuery());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.SQL_DB_COMMAND, operation.getCaseType());
    }

    @Test
    public void testExecuteUpdate1() throws SQLException {
        PreparedStatement stmt = CONNECTION.prepareStatement(QUERIES.get(4));
        stmt.executeUpdate();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        SQLOperation operation = (SQLOperation) operations.get(0);
        Assert.assertEquals("Invalid executed parameters.", QUERIES.get(4),operation.getQuery());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.SQL_DB_COMMAND, operation.getCaseType());
    }
}
