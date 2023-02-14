package com.nr.instrumentation.security.postgresql80312;

import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.api.agent.Trace;
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

import java.math.BigDecimal;
import java.sql.Connection;
import java.sql.Date;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Time;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = "org.postgresql")
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class PgStatementTest {
    private static final String DB_USER = "postgres";
    private static final String DB_PASSWORD = "postgres";
    private static final String DB_NAME = "test";
    private static final List<String> QUERIES = new ArrayList<>();
    @ClassRule
    public static PostgreSQLContainer postgreSQLContainer = new PostgreSQLContainer("postgres:11.1")
            .withDatabaseName(DB_NAME)
            .withUsername(DB_USER)
            .withPassword(DB_PASSWORD);
    private static Connection CONNECTION;

    @AfterClass
    public static void cleanup() throws SQLException {
        if (CONNECTION != null) {
            CONNECTION.close();
        }
        if (postgreSQLContainer != null) {
            postgreSQLContainer.close();
        }
    }

    public static void getConnection() {
        try {
            Class.forName("org.postgresql.Driver");
            CONNECTION = DriverManager.getConnection(postgreSQLContainer.getJdbcUrl(), DB_USER, DB_PASSWORD);
        } catch (Exception e) {
            System.out.println("Error in DB connection: " + e);
        }
    }

    @BeforeClass
    public static void initData() throws SQLException {
        getConnection();
        QUERIES.add(
                "CREATE TABLE IF NOT EXISTS USERS(id int primary key, first_name varchar(255), last_name varchar(255), dob date, dot time, dotz timestamptz, active boolean, arr bytea)");
        QUERIES.add("TRUNCATE TABLE USERS");
        QUERIES.add("INSERT INTO USERS(id, first_name, last_name) VALUES(1, 'john', 'doe')");
        QUERIES.add("SELECT * FROM USERS");
        QUERIES.add("UPDATE USERS SET \"last_name\"='Doe' WHERE id=1");
        QUERIES.add(
                "select * from users where id=? and id=? and id=? and id=? and id=? and id=? and first_name=? and first_name=? and id=? and dob=? and arr=? and active=? and dot=? and dotz=?");
        QUERIES.add("SELECT * FROM USERS WHERE id=?");

        // set up data in h2
        Statement stmt = CONNECTION.createStatement();
        stmt.execute(QUERIES.get(0));
        stmt.execute(QUERIES.get(1));
        stmt.execute(QUERIES.get(2));
        stmt.close();
    }

    @Test
    public void testExecute() throws SQLException {
        callExecute();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        SQLOperation operation = (SQLOperation) operations.get(0);
        Assert.assertEquals("Invalid executed parameters.", QUERIES.get(3), operation.getQuery());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.SQL_DB_COMMAND, operation.getCaseType());
    }

    @Trace(dispatcher = true)
    private void callExecute() throws SQLException {
        Statement stmt = CONNECTION.createStatement();
        stmt.execute(QUERIES.get(3));
    }

    @Test
    public void testExecute1() throws SQLException {
        callExecute1();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        SQLOperation operation = (SQLOperation) operations.get(0);
        Assert.assertEquals("Invalid executed parameters.", QUERIES.get(3), operation.getQuery());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.SQL_DB_COMMAND, operation.getCaseType());
    }

    @Trace(dispatcher = true)
    private void callExecute1() throws SQLException {
        PreparedStatement stmt = CONNECTION.prepareStatement(QUERIES.get(3));
        stmt.execute();
    }

    @Test
    public void testExecuteQuery() throws SQLException {
        callExecuteQuery();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        SQLOperation operation = (SQLOperation) operations.get(0);
        Assert.assertEquals("Invalid executed parameters.", QUERIES.get(3), operation.getQuery());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.SQL_DB_COMMAND, operation.getCaseType());
    }

    @Trace(dispatcher = true)
    private void callExecuteQuery() throws SQLException {
        Statement stmt = CONNECTION.createStatement();
        stmt.executeQuery(QUERIES.get(3));
    }

    @Test
    public void testExecuteQuery1() throws SQLException {
        callExecuteQuery1();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        SQLOperation operation = (SQLOperation) operations.get(0);
        Assert.assertEquals("Invalid executed parameters.", QUERIES.get(3), operation.getQuery());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.SQL_DB_COMMAND, operation.getCaseType());
    }

    @Trace(dispatcher = true)
    private void callExecuteQuery1() throws SQLException {
        PreparedStatement stmt = CONNECTION.prepareStatement(QUERIES.get(3));
        stmt.executeQuery();
    }

    @Test
    public void testExecuteUpdate() throws SQLException {
        callExecuteUpdate();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        SQLOperation operation = (SQLOperation) operations.get(0);
        Assert.assertEquals("Invalid executed parameters.", QUERIES.get(4), operation.getQuery());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.SQL_DB_COMMAND, operation.getCaseType());
    }

    @Trace(dispatcher = true)
    private void callExecuteUpdate() throws SQLException {
        Statement stmt = CONNECTION.createStatement();
        stmt.executeUpdate(QUERIES.get(4));
    }

    @Test
    public void testExecuteUpdate1() throws SQLException {
        callExecuteUpdate1();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        SQLOperation operation = (SQLOperation) operations.get(0);
        Assert.assertEquals("Invalid executed parameters.", QUERIES.get(4), operation.getQuery());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.SQL_DB_COMMAND, operation.getCaseType());
    }

    @Trace(dispatcher = true)
    private void callExecuteUpdate1() throws SQLException {
        PreparedStatement stmt = CONNECTION.prepareStatement(QUERIES.get(4));
        stmt.executeUpdate();
    }

    @Test
    public void testParams() throws SQLException {
        Map<Integer, String> params = callParams();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        SQLOperation operation = (SQLOperation) operations.get(0);
        Assert.assertEquals("Invalid executed parameters.", params, operation.getParams());
        Assert.assertEquals("Invalid executed query.", QUERIES.get(5), operation.getQuery());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.SQL_DB_COMMAND, operation.getCaseType());
    }

    @Trace(dispatcher = true)
    private Map<Integer, String> callParams() throws SQLException {
        Map<Integer, String> params = new HashMap<Integer, String>();
        PreparedStatement stmt = CONNECTION.prepareStatement(QUERIES.get(5));
        stmt.setInt(1, 1);
        params.put(1, "1");

        stmt.setShort(2, (short) 3);
        params.put(2, "3");

        stmt.setLong(3, 1789);
        params.put(3, "1789");

        stmt.setBigDecimal(4, BigDecimal.valueOf(10));
        params.put(4, "10");

        stmt.setFloat(5, 14);
        params.put(5, "14.0");

        stmt.setDouble(6, 51);
        params.put(6, "51.0");

        stmt.setString(7, "monu");
        params.put(7, "monu");

        stmt.setNull(8, 1);
        params.put(8, "null");

        byte b = new Integer(34).byteValue();
        stmt.setByte(9, b);
        params.put(9, String.valueOf(b));

        Date dob = new Date(System.currentTimeMillis());
        stmt.setDate(10, dob);
        params.put(10, dob.toString());

        Date time = new Date(System.currentTimeMillis());
        String str = time.toString();
        byte[] myByte = str.getBytes();
        stmt.setBytes(11, myByte);
        params.put(11, new String(myByte));

        stmt.setBoolean(12, true);
        params.put(12, "true");

        Time dot = new Time(System.currentTimeMillis());
        stmt.setTime(13, dot);
        params.put(13, dot.toString());

        Timestamp dotz = new Timestamp(System.currentTimeMillis());
        stmt.setTimestamp(14, dotz);
        params.put(14, dotz.toString());

        stmt.execute();
        System.out.println(params);
        return params;
    }

    @Test
    public void testClearParams() throws SQLException {
        Map<Integer, String> params = callClearParams();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        SQLOperation operation = (SQLOperation) operations.get(0);
        Assert.assertEquals("Invalid executed parameters.", params, operation.getParams());
        Assert.assertEquals("Invalid executed query.", QUERIES.get(6), operation.getQuery());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.SQL_DB_COMMAND, operation.getCaseType());
    }

    @Trace(dispatcher = true)
    private Map<Integer, String> callClearParams() throws SQLException {
        Map<Integer, String> params = new HashMap<Integer, String>();
        PreparedStatement stmt = CONNECTION.prepareStatement(QUERIES.get(6));
        stmt.setInt(1, 9);
        stmt.clearParameters();
        stmt.setInt(1, 1);
        params.put(1, "1");

        stmt.execute();
        System.out.println(params);
        return params;
    }
}
