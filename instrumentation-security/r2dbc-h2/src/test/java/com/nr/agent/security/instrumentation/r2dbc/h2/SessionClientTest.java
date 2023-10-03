package com.nr.agent.security.instrumentation.r2dbc.h2;

import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.api.agent.Trace;
import com.newrelic.api.agent.security.schema.R2DBCVendor;
import io.r2dbc.h2.H2ConnectionConfiguration;
import io.r2dbc.h2.H2ConnectionFactory;
import io.r2dbc.spi.Connection;
import io.r2dbc.spi.ConnectionFactories;
import io.r2dbc.spi.ConnectionFactory;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.List;

@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = "io.r2dbc.h2")
public class SessionClientTest {

    private static Connection connection;
    String DB_NAME = "test";

    private final List<String> QUERIES = new ArrayList<>();

    @Before
    public void setup() {
        QUERIES.add("CREATE TABLE IF NOT EXISTS USERS(id int primary key, first_name varchar(255), last_name varchar(255))");
        QUERIES.add("INSERT INTO USERS(id, first_name, last_name) VALUES(1, 'Max', 'Power')");
        QUERIES.add("SELECT * FROM USERS");
    }

    @After
    public void teardown() {
        Mono.from(connection.close()).block();
    }

    @Test
    public void testSessionClient() {
        setConnection();
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        Assert.assertEquals("Wrong R2DBCVendor vendor", introspector.getR2DBCVendor(), R2DBCVendor.H2);
    }
    @Test
    public void testSessionClient1() {
        setConnection1();
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        Assert.assertEquals("Wrong R2DBCVendor vendor", introspector.getR2DBCVendor(), R2DBCVendor.H2);
    }

    @Trace(dispatcher = true)
    private void setConnection() {
        connect();
        Mono.from(connection.createStatement(QUERIES.get(1)).execute()).block();
        Mono.from(connection.close()).block();
    }

    @Trace(dispatcher = true)
    private void setConnection1() {
        connect1();
        Mono.from(connection.createStatement(QUERIES.get(2)).execute()).block();
        Mono.from(connection.close()).block();
    }

    private void connect() {
        ConnectionFactory connectionFactory = new H2ConnectionFactory(
                H2ConnectionConfiguration.builder()
                        .inMemory(DB_NAME)
                        .build()
        );
        connection = Mono.from(connectionFactory.create()).block();
        Mono.from(connection.createStatement(QUERIES.get(0)).execute()).block();
    }

    private void connect1() {
        String url = "r2dbc:h2:mem:///test";
        ConnectionFactory connectionFactory = ConnectionFactories.get(url);
        connection = Mono.from(connectionFactory.create()).block();
        Mono.from(connection.createStatement(QUERIES.get(0)).execute()).block();
    }
}