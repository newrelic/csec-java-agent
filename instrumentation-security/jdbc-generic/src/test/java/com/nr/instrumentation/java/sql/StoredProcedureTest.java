package com.nr.instrumentation.java.sql;

import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.api.agent.Trace;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.security.schema.operation.BatchSQLOperation;
import com.newrelic.api.agent.security.schema.operation.SQLOperation;
import org.h2.jdbc.JdbcPreparedStatement;
import org.h2.jdbc.JdbcStatement;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;

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
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;

@RunWith(SecurityInstrumentationTestRunner.class)
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@InstrumentationTestConfig(includePrefixes = { "javax.sql", "java.sql" })
public class StoredProcedureTest {
    private static final String DB_DRIVER = "org.h2.Driver";
    private static final String DB_CONNECTION = "jdbc:h2:mem:test;DB_CLOSE_DELAY=-1";
    private static final String DB_USER = "";
    private static final String DB_PASSWORD = "";
    private static final Connection CONNECTION = getDBConnection();

    private static final List<String> QUERIES = new ArrayList<>();
    private static final List<String> FAIL_QUERIES = new ArrayList<>();

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
        QUERIES.add("CREATE ALIAS getH2Version FOR \"org.h2.engine.Constants.getVersion\"");
        QUERIES.add("call getH2Version()");
        QUERIES.add(" call getH2Version() ");
        QUERIES.add("{call getH2Version()}");
        QUERIES.add("{ call getH2Version() }");
        QUERIES.add(" { call getH2Version() } ");

        QUERIES.add("CALL getH2Version()");
        QUERIES.add(" CALL getH2Version() ");
        QUERIES.add("{CALL getH2Version()}");
        QUERIES.add("{ CALL getH2Version() }");
        QUERIES.add(" { CALL getH2Version() } ");

        FAIL_QUERIES.add("CREATE TABLE IF NOT EXISTS MYUSERS(id int primary key, first_name varchar(255), last_name varchar(255))");
        FAIL_QUERIES.add("{select * from myusers where first_name='call'}");
        FAIL_QUERIES.add("{select * from myusers where first_name='{call'}");
        FAIL_QUERIES.add("select * from myusers where first_name='call'");
        FAIL_QUERIES.add("select * from myusers where first_name='{call'");
        FAIL_QUERIES.add("SELECT * FROM MYUSERS WHERE first_name='call'");
        FAIL_QUERIES.add("SELECT * FROM MYUSERS WHERE first_name='{call'");
        FAIL_QUERIES.add("{SELECT * FROM MYUSERS WHERE first_name='call'}");
        FAIL_QUERIES.add("{SELECT * FROM MYUSERS WHERE first_name='{call'}");

        // set up data in h2
        Statement stmt = CONNECTION.createStatement();
        stmt.execute(QUERIES.get(0));
        stmt.execute(FAIL_QUERIES.get(0));
        stmt.close();
    }

    @Test
    public void testProcedureCasePass() throws SQLException {
        for (int i = 1; i < QUERIES.size(); i++) {
            _case1(QUERIES.get(i));
            SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
            List<AbstractOperation> operations = introspector.getOperations();
            Assert.assertTrue("No operations detected", operations.size() > 0);

            SQLOperation operation = (SQLOperation) operations.get(i-1);

            Assert.assertEquals(String.format("[case-%d] Invalid executed parameters.", i), QUERIES.get(i), operation.getQuery());
            Assert.assertEquals(String.format("[case-%d] Invalid event category.", i), VulnerabilityCaseType.SQL_DB_COMMAND, operation.getCaseType());
            Assert.assertTrue(String.format("[case-%d] Expected a stored procedure call.", i), operation.isStoredProcedureCall());
            Assert.assertEquals(String.format("[case-%d] Invalid executed class name.", i), JdbcStatement.class.getName(), operation.getClassName());
            Assert.assertEquals(String.format("[case-%d] Invalid executed method name.", i), "execute", operation.getMethodName());
        }
    }

    @Test
    public void testProcedureCaseFail() throws SQLException {
        for (int i = 1; i < FAIL_QUERIES.size(); i++) {
            _case1(FAIL_QUERIES.get(i));
            SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
            List<AbstractOperation> operations = introspector.getOperations();
            Assert.assertTrue("No operations detected", operations.size() > 0);

            SQLOperation operation = (SQLOperation) operations.get(i-1);

            Assert.assertEquals(String.format("[case-%d] Invalid executed parameters.", i), FAIL_QUERIES.get(i), operation.getQuery());
            Assert.assertEquals(String.format("[case-%d] Invalid event category.", i), VulnerabilityCaseType.SQL_DB_COMMAND, operation.getCaseType());
            Assert.assertFalse(String.format("[case-%d] Expected a stored procedure call.", i), operation.isStoredProcedureCall());
            Assert.assertEquals(String.format("[case-%d] Invalid executed class name.", i), JdbcStatement.class.getName(), operation.getClassName());
            Assert.assertEquals(String.format("[case-%d] Invalid executed method name.", i), "execute", operation.getMethodName());
        }
    }

    @Test
    public void testPreparedProcedureCasePass() throws SQLException {
        for (int i = 1; i < QUERIES.size(); i++) {
            _case2(QUERIES.get(i));
            SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
            List<AbstractOperation> operations = introspector.getOperations();
            Assert.assertTrue("No operations detected", operations.size() > 0);

            SQLOperation operation = (SQLOperation) operations.get(i-1);

            Assert.assertEquals(String.format("[case-%d] Invalid executed parameters.", i), QUERIES.get(i), operation.getQuery());
            Assert.assertEquals(String.format("[case-%d] Invalid event category.", i), VulnerabilityCaseType.SQL_DB_COMMAND, operation.getCaseType());
            Assert.assertTrue(String.format("[case-%d] Expected a stored procedure call.", i), operation.isStoredProcedureCall());
            Assert.assertEquals(String.format("[case-%d] Invalid executed class name.", i), JdbcPreparedStatement.class.getName(), operation.getClassName());
            Assert.assertEquals(String.format("[case-%d] Invalid executed method name.", i), "execute", operation.getMethodName());
        }
    }

    @Test
    public void testPreparedProcedureCaseFail() throws SQLException {
        for (int i = 1; i < FAIL_QUERIES.size(); i++) {
            _case2(FAIL_QUERIES.get(i));
            SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
            List<AbstractOperation> operations = introspector.getOperations();
            Assert.assertTrue("No operations detected", operations.size() > 0);

            SQLOperation operation = (SQLOperation) operations.get(i-1);

            Assert.assertEquals(String.format("[case-%d] Invalid executed parameters.", i), FAIL_QUERIES.get(i), operation.getQuery());
            Assert.assertEquals(String.format("[case-%d] Invalid event category.", i), VulnerabilityCaseType.SQL_DB_COMMAND, operation.getCaseType());
            Assert.assertFalse(String.format("[case-%d] Expected a stored procedure call.", i), operation.isStoredProcedureCall());
            Assert.assertEquals(String.format("[case-%d] Invalid executed class name.", i), JdbcPreparedStatement.class.getName(), operation.getClassName());
            Assert.assertEquals(String.format("[case-%d] Invalid executed method name.", i), "execute", operation.getMethodName());
        }
    }

    @Trace(dispatcher = true)
    private void _case1(String sql) throws SQLException {
        Statement stmt = CONNECTION.createStatement();
        stmt.execute(sql);
        stmt.close();
    }

    @Trace(dispatcher = true)
    private void _case2(String sql) throws SQLException {
        PreparedStatement stmt = CONNECTION.prepareStatement(sql);
        stmt.execute();
        stmt.close();
    }
}
