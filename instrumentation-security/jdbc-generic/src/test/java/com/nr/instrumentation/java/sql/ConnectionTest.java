package com.nr.instrumentation.java.sql;

import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.api.agent.Trace;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.security.schema.operation.SQLOperation;
import org.h2.jdbc.JdbcCallableStatement;
import org.h2.jdbc.JdbcPreparedStatement;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

@RunWith(SecurityInstrumentationTestRunner.class)
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@InstrumentationTestConfig(includePrefixes = { "javax.sql", "java.sql" })
public class ConnectionTest {

    private static final String DB_DRIVER = "org.h2.Driver";
    private static final String DB_CONNECTION = "jdbc:h2:mem:test;DB_CLOSE_DELAY=-1";
    private static final String DB_USER = "";
    private static final String DB_PASSWORD = "";
    private static final Connection CONNECTION = getDBConnection();

    private static final List<String> QUERIES = new ArrayList<>();

    @AfterClass
    public static void teardown() throws SQLException {
        CONNECTION.close();
    }

    private static Connection getDBConnection() {
        Connection dbConnection = null;
        try {
            Class.forName(DB_DRIVER);
            dbConnection = DriverManager.getConnection(DB_CONNECTION, DB_USER, DB_PASSWORD);
            return dbConnection;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return dbConnection;
    }

    @BeforeClass
    public static void initData() throws SQLException {
        QUERIES.add("CREATE TABLE IF NOT EXISTS USERS(id int primary key, first_name varchar(255), last_name varchar(255))");
        QUERIES.add("TRUNCATE TABLE USERS");
        QUERIES.add("INSERT INTO USERS(id, first_name, last_name) VALUES(1, 'john', 'doe')");
        QUERIES.add("select * from USERS");
        // set up data in h2
        Statement stmt = CONNECTION.createStatement();
        stmt.execute(QUERIES.get(0));
        stmt.execute(QUERIES.get(1));
        stmt.execute(QUERIES.get(2));
        stmt.close();
    }

    @Test
    public void testPrepareStatement() throws SQLException {
        prepareStatement();
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        SQLOperation operation = (SQLOperation) operations.get(0);

        Assert.assertEquals("Invalid executed parameters.", QUERIES.get(3), operation.getQuery());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.SQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed class name.", JdbcPreparedStatement.class.getName(), operation.getClassName());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());

    }

    @Test
    public void testPrepareCall() throws SQLException {
        prepareCall();
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        SQLOperation operation = (SQLOperation) operations.get(0);

        Assert.assertEquals("Invalid executed parameters.", QUERIES.get(3), operation.getQuery());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.SQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed class name.", JdbcCallableStatement.class.getName(), operation.getClassName());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
    }

    @Test
    public void testPrepareStatement2() throws SQLException {
        prepareStatement2();
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        SQLOperation operation = (SQLOperation) operations.get(0);

        Assert.assertEquals("Invalid executed parameters.", QUERIES.get(3), operation.getQuery());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.SQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed class name.", JdbcPreparedStatement.class.getName(), operation.getClassName());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
    }

    @Test

    public void testPrepareCall2() throws SQLException {
        prepareCall2();
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        SQLOperation operation = (SQLOperation) operations.get(0);

        Assert.assertEquals("Invalid executed parameters.", QUERIES.get(3), operation.getQuery());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.SQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed class name.", JdbcCallableStatement.class.getName(), operation.getClassName());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
    }

    @Test

    public void testPrepareCallNames() throws SQLException {
        prepareCallColNames();
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        SQLOperation operation = (SQLOperation) operations.get(0);

        Assert.assertEquals("Invalid executed parameters.", QUERIES.get(3), operation.getQuery());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.SQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed class name.", JdbcPreparedStatement.class.getName(), operation.getClassName());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
    }

    @Test
    public void testPrepareCallIndex() throws SQLException {
        prepareCallColIndex();
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        SQLOperation operation = (SQLOperation) operations.get(0);

        Assert.assertEquals("Invalid executed parameters.", QUERIES.get(3), operation.getQuery());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.SQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed class name.", JdbcPreparedStatement.class.getName(), operation.getClassName());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
    }

    @Trace(dispatcher = true)
    private void prepareStatement() throws SQLException {
        PreparedStatement stmt = CONNECTION.prepareStatement(QUERIES.get(3), ResultSet.TYPE_FORWARD_ONLY, ResultSet.CONCUR_READ_ONLY);
        stmt.execute();
        stmt.close();
    }

    @Trace(dispatcher = true)
    private void prepareCall() throws SQLException {
        PreparedStatement stmt = CONNECTION.prepareCall(QUERIES.get(3), ResultSet.TYPE_SCROLL_INSENSITIVE, ResultSet.CONCUR_UPDATABLE);
        stmt.execute();
        stmt.close();
    }

    @Trace(dispatcher = true)
    private void prepareStatement2() throws SQLException {
        PreparedStatement stmt = CONNECTION.prepareStatement(QUERIES.get(3), ResultSet.TYPE_SCROLL_SENSITIVE, ResultSet.CONCUR_READ_ONLY, ResultSet.HOLD_CURSORS_OVER_COMMIT);
        stmt.execute();
        stmt.close();
    }

    @Trace(dispatcher = true)
    private void prepareCall2() throws SQLException {
        PreparedStatement stmt = CONNECTION.prepareCall(QUERIES.get(3), ResultSet.TYPE_SCROLL_INSENSITIVE, ResultSet.CONCUR_UPDATABLE, ResultSet.CLOSE_CURSORS_AT_COMMIT);
        stmt.execute();
        stmt.close();
    }

    @Trace(dispatcher = true)
    private void prepareCallColIndex() throws SQLException {
        int[] columnIndexes = { 1, 2 };
        PreparedStatement stmt = CONNECTION.prepareStatement(QUERIES.get(3), columnIndexes);
        stmt.execute();
        stmt.close();
    }

    @Trace(dispatcher = true)
    private void prepareCallColNames() throws SQLException {
        String[] columnNames = { "id", "first_name", "last_name" };
        PreparedStatement stmt = CONNECTION.prepareStatement(QUERIES.get(3), columnNames);
        stmt.execute();
        stmt.close();
    }
}


