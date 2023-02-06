package com.nr.instrumentation.java.sql;

import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.api.agent.Trace;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.security.schema.operation.SQLOperation;
import org.h2.jdbc.JdbcPreparedStatement;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;

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
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = { "javax.sql", "java.sql" })
public class PreparedStatementTest {
    private static final String DB_DRIVER = "org.h2.Driver";
    private static final String DB_CONNECTION = "jdbc:h2:mem:test;DB_CLOSE_DELAY=-1";
    private static final String DB_USER = "";
    private static final String DB_PASSWORD = "";
    private static final Connection CONNECTION = getDBConnection();

    private static List<String> QUERIES = new ArrayList<>();

    private static AtomicInteger id = new AtomicInteger(3);

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
    public static void initData() throws SQLException {QUERIES.add(
            "CREATE TABLE IF NOT EXISTS USERS(id int primary key, first_name varchar(255), last_name varchar(255), dob date, dot time, dotz timestamp, active boolean, arr bytea)");
        QUERIES.add("TRUNCATE TABLE USERS");
        QUERIES.add("INSERT INTO USERS(id, first_name, last_name) VALUES(1, 'john', 'doe')");
        QUERIES.add("select * from users");
        QUERIES.add("UPDATE USERS SET last_name='Doe' WHERE id=1");
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
    public void testExecuteQuery() throws SQLException {
        executeQuery();
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        SQLOperation operation = (SQLOperation) operations.get(0);

        Assert.assertEquals("Invalid executed parameters.", QUERIES.get(3), operation.getQuery());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.SQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed class name.", JdbcPreparedStatement.class.getName(), operation.getClassName());
        Assert.assertEquals("Invalid executed method name.", "executeQuery", operation.getMethodName());
    }

    @Test
    public void testExecuteUpdate() throws SQLException {
        executeUpdate();
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        SQLOperation operation = (SQLOperation) operations.get(0);

        Assert.assertEquals("Invalid executed parameters.", QUERIES.get(4), operation.getQuery());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.SQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid executed class name.", JdbcPreparedStatement.class.getName(), operation.getClassName());
        Assert.assertEquals("Invalid executed method name.", "executeUpdate", operation.getMethodName());
    }

    @Test
    public void testExecute() throws SQLException {
        execute();
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
    private void executeQuery() throws SQLException {
        PreparedStatement stmt = CONNECTION.prepareStatement(QUERIES.get(3));
        stmt.executeQuery();
        stmt.close();
    }

    @Trace(dispatcher = true)
    private void executeUpdate() throws SQLException {
        PreparedStatement stmt = CONNECTION.prepareStatement(QUERIES.get(4));
        stmt.executeUpdate();
        stmt.close();
    }

    @Trace(dispatcher = true)
    private void execute() throws SQLException {
        PreparedStatement stmt = CONNECTION.prepareStatement(QUERIES.get(3));
        stmt.execute();
        stmt.close();
    }

    @Test
    public void testParams() throws SQLException {
        Map<Integer, String> params = callParams();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        SQLOperation operation = (SQLOperation) operations.get(0);
        Map<Integer, String> actualParams = operation.getParams();
        try {
            Assert.assertEquals("Invalid executed parameters.", params, actualParams);
        } catch (AssertionError e){
            HashSet<Integer> unionKeys = new HashSet<>(actualParams.keySet());
            unionKeys.addAll(params.keySet());
            unionKeys.removeAll(actualParams.keySet());
            Assert.fail("Invalid executed parameters. Missing index: "+unionKeys);
        }
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
