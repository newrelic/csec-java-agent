package com.nr.agent.security.instrumentation.r2dbc.h2;

import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.api.agent.Trace;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.R2DBCVendor;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.security.schema.operation.SQLOperation;
import io.r2dbc.h2.client.Client;
import io.r2dbc.h2.client.SessionClient;
import io.r2dbc.spi.Connection;
import io.r2dbc.spi.ConnectionFactories;
import io.r2dbc.spi.ConnectionFactory;
import org.h2.engine.ConnectionInfo;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = "io.r2dbc.h2")
public class ClientTest {
    public static Connection connection;
    private static final List<String> QUERIES = new ArrayList<>();
    private final String DB_CONNECTION = "jdbc:h2:mem:test;DB_CLOSE_DELAY=-1";
    private final String DB_USER = "";
    private final String DB_PASSWORD = "";
    @BeforeClass
    public static void setup() {
        QUERIES.add("CREATE TABLE IF NOT EXISTS USERS(id int primary key, first_name varchar(255), last_name varchar(255))");
        QUERIES.add("TRUNCATE TABLE USERS");
        QUERIES.add("INSERT INTO USERS(id, first_name, last_name) VALUES(1, 'Max', 'Power')");
        QUERIES.add("SELECT * FROM USERS");
        QUERIES.add("UPDATE USERS SET first_name = 'Test' WHERE last_name = 'Power'");

        ConnectionFactory connectionFactory = ConnectionFactories.get("r2dbc:h2:mem:///test");
        connection = Mono.from(connectionFactory.create()).block();
        Mono.from(connection.createStatement(QUERIES.get(0)).execute()).block();
        Mono.from(connection.createStatement(QUERIES.get(1)).execute()).block();
    }

    @AfterClass
    public static void teardown() {
        Mono.from(connection.close()).block();
    }
    @Test
    public void testSessionClient() {
        clientSession();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertNotNull(operations.get(0));
        Assert.assertEquals("Got wrong vendor", introspector.getR2DBCVendor(), R2DBCVendor.H2);

        SQLOperation operation = (SQLOperation) operations.get(0);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.SQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid db-Name", "H2", operation.getDbName());
        Assert.assertEquals("Invalid method-Name.", "execute", operation.getMethodName());
        Assert.assertEquals("Invalid executed parameters.", QUERIES.get(1), operation.getQuery());
    }

    @Test
    public void testSessionClient1() {
        clientSession1();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertNotNull(operations.get(0));
        Assert.assertEquals("Got wrong vendor", introspector.getR2DBCVendor(),R2DBCVendor.H2);

        SQLOperation operation = (SQLOperation) operations.get(0);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.SQL_DB_COMMAND, operation.getCaseType());
        Assert.assertEquals("Invalid db-Name", "H2", operation.getDbName());
        Assert.assertEquals("Invalid method-Name.", "execute", operation.getMethodName());
        Assert.assertEquals("Invalid executed parameters.", QUERIES.get(2), operation.getQuery());
    }

    @Trace(dispatcher = true)
    private void clientSession() {
        Client client = new SessionClient(new ConnectionInfo(DB_CONNECTION, new Properties()), true);
        client.execute(QUERIES.get(1));
    }

    @Trace(dispatcher = true)
    private void clientSession1() {
        Properties props = new Properties();
        props.setProperty("user", DB_USER);
        props.setProperty("password", DB_PASSWORD);
        Client client = new SessionClient(new ConnectionInfo(DB_CONNECTION, props), true);
        client.execute(QUERIES.get(2));
    }

}
