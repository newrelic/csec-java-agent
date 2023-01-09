package com.nr.instrumentation.security.postgresql941207;

import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.JDBCVendor;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.security.schema.operation.SQLOperation;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.testcontainers.containers.PostgreSQLContainer;
import ru.yandex.qatools.embed.postgresql.EmbeddedPostgres;

import java.io.IOException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.List;

import static ru.yandex.qatools.embed.postgresql.distribution.Version.Main.V9_6;

@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = "org.postgresql")
public class DriverTest {
    private static final String DB_USER = "postgres";
    private static final String DB_PASSWORD = "postgres";
    @ClassRule
    public static PostgreSQLContainer postgreSQLContainer = new PostgreSQLContainer("postgres:11.1")
            .withDatabaseName("test")
            .withUsername(DB_USER)
            .withPassword(DB_PASSWORD);
    private static Connection CONNECTION;
    private static EmbeddedPostgres postgres;

    @AfterClass
    public static void cleanup() throws SQLException {
        CONNECTION.close();
        postgres.stop();
    }

    @Test
    public void testConnect() throws SQLException {
        Connection c = null;
        try {
            Class.forName("org.postgresql.Driver");
            c = DriverManager.getConnection(postgreSQLContainer.getJdbcUrl(), DB_USER, DB_PASSWORD);
        } catch (Exception e) {
            System.out.println("Error in DB connection: "+e);
        } finally {
            c.close();
        }

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String vendor = introspector.getJDBCVendor();
        Assert.assertEquals("Incorrect DB vendor", vendor, JDBCVendor.POSTGRES);
    }

    @Test
    public void testExecute() throws SQLException {
        getConnection();
        Statement stmt = CONNECTION.createStatement();
        stmt.execute("select * from user");

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        SQLOperation operation = (SQLOperation) operations.get(0);
        Assert.assertEquals("Invalid executed parameters.", "select * from user",operation.getQuery());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.SQL_DB_COMMAND, operation.getCaseType());
    }

    @Test
    public void testEmbedded() throws IOException, SQLException {
        postgres = new EmbeddedPostgres(V9_6);

        final String url = postgres.start("localhost", 5432, "dbName", "userName", "password");

        final Connection conn = DriverManager.getConnection(url);
        conn.createStatement().execute("CREATE TABLE IF NOT EXISTS films (code char(5));");
        conn.close();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        SQLOperation operation = (SQLOperation) operations.get(0);
        Assert.assertEquals("Invalid executed parameters.", "CREATE TABLE IF NOT EXISTS films (code char(5));", operation.getQuery());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.SQL_DB_COMMAND, operation.getCaseType());
    }

    private void getConnection(){
        try {
            Class.forName("org.postgresql.Driver");
            CONNECTION = DriverManager.getConnection(postgreSQLContainer.getJdbcUrl(), DB_USER, DB_PASSWORD);
        } catch (Exception e) {
            System.out.println("Error in DB connection: "+e);
        }
    }
}
