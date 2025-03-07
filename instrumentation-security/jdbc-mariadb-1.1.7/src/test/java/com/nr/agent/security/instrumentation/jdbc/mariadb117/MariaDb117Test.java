package com.nr.agent.security.instrumentation.jdbc.mariadb117;

import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.api.agent.security.schema.JDBCVendor;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.testcontainers.containers.MariaDBContainer;
import org.testcontainers.utility.DockerImageName;
import org.testcontainers.utility.MountableFile;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.Collections;

@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = {"org.mariadb.jdbc"})
public class MariaDb117Test {

    private static String connectionString;

    public static MariaDBContainer<?> mariaDb;

    private static String DB_USER;

    private static String DB_PASSWORD;

    @BeforeClass
    public static void setUpDb() {

        int PORT = SecurityInstrumentationTestRunner.getIntrospector().getRandomPort();
        mariaDb = new MariaDBContainer<>(DockerImageName.parse("mariadb:10.5.5"));
        mariaDb.setPortBindings(Collections.singletonList(PORT + ":3808"));

        mariaDb.withCopyFileToContainer(MountableFile.forClasspathResource("maria-db-test.sql"), "/var/lib/mysql/");
        mariaDb.start();
        DB_USER = mariaDb.getUsername();
        DB_PASSWORD = mariaDb.getPassword();

        connectionString = mariaDb.getJdbcUrl();
    }

    @AfterClass
    public static void tearDownDb() {
        if (mariaDb != null && mariaDb.isCreated()) {
            mariaDb.stop();
        }
    }

    @Test
    public void testConnect() throws SQLException, ClassNotFoundException {
        Class.forName("org.mariadb.jdbc.Driver");
        try (Connection ignored = DriverManager.getConnection(connectionString, DB_USER, DB_PASSWORD)){
            SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
            String vendor = introspector.getJDBCVendor();
            Assert.assertEquals("Incorrect DB vendor", vendor, JDBCVendor.MARIA_DB);
        }
    }
}
