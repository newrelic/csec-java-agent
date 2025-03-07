package com.nr.agent.security.instrumentation.jdbc.mysql602;

import com.mysql.cj.fabric.jdbc.FabricMySQLDataSource;
import com.mysql.cj.jdbc.MysqlConnectionPoolDataSource;
import com.mysql.cj.jdbc.MysqlDataSource;
import com.mysql.cj.jdbc.MysqlXADataSource;
import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.api.agent.Trace;
import com.newrelic.api.agent.security.schema.JDBCVendor;
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

import java.io.IOException;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.Collections;

@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = {"com.mysql.cj"})
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class MySql602DataStoreTest {

    private static String DB_CONNECTION;

    private static String DB_NAME;

    private static String DB_USER;

    private static String DB_PASSWORD;

    private static MySQLContainer<?> mysql;

    @BeforeClass
    public static void setUpDb() {
        System.setProperty("DOCKER_DEFAULT_PLATFORM", "linux/amd64");
        mysql = new MySQLContainer<>(DockerImageName.parse("mysql:5.7.43"))
                .withCommand("--default-authentication-plugin=mysql_native_password")
                .withCopyFileToContainer(MountableFile.forClasspathResource("maria-db-test.sql"), "/docker-entrypoint-initdb.d/");
        mysql.start();

        DB_PASSWORD = mysql.getPassword();
        DB_USER = mysql.getUsername();
        DB_NAME = mysql.getDatabaseName();
        DB_CONNECTION = mysql.getJdbcUrl()+"?useSSL=false";
    }

    @AfterClass
    public static void tearDownDb() {
        if (mysql != null && mysql.isCreated()) {
            mysql.close();
            mysql.stop();
        }
    }

    @Test
    public void testGetConnectionMysqlDataSource() {
        try {
            callGetConnectionMysqlDataSource();
        } catch (Exception ignored) {
        }

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String vendor = introspector.getJDBCVendor();
        Assert.assertEquals("Incorrect DB vendor", JDBCVendor.MYSQL, vendor);
    }

    @Test
    public void testGetConnectionMysqlDataSource1() {
        try {
            callGetConnectionMysqlDataSource1();
        } catch (Exception ignored) {
        }

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String vendor = introspector.getJDBCVendor();
        Assert.assertEquals("Incorrect DB vendor", JDBCVendor.MYSQL, vendor);
    }

    @Test
    public void testGetConnectionFabricMySQLDataSource() {
        try {
            callGetConnectionFabricMySQLDataSource();
        } catch (Exception ignored) {
        }

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String vendor = introspector.getJDBCVendor();
        Assert.assertEquals("Incorrect DB vendor", JDBCVendor.MYSQL, vendor);
    }

    @Test
    public void testGetConnectionFabricMySQLDataSource1() {
        try {
            callGetConnectionFabricMySQLDataSource1();
        } catch (Exception ignored) {
        }

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String vendor = introspector.getJDBCVendor();
        Assert.assertEquals("Incorrect DB vendor", JDBCVendor.MYSQL, vendor);
    }

    @Test
    public void testGetConnectionMysqlConnectionPoolDataSource() {
        try {
            callGetConnectionMysqlConnectionPoolDataSource();
        } catch (Exception ignored) {
        }

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String vendor = introspector.getJDBCVendor();
        Assert.assertEquals("Incorrect DB vendor", JDBCVendor.MYSQL, vendor);
    }

    @Test
    public void testGetConnectionMysqlConnectionPoolDataSource1() {
        try {
            callGetConnectionMysqlConnectionPoolDataSource1();
        } catch (Exception ignored) {
        }

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String vendor = introspector.getJDBCVendor();
        Assert.assertEquals("Incorrect DB vendor", JDBCVendor.MYSQL, vendor);
    }

    @Test
    public void testGetConnectionMysqlXADataSource() {
        try {
            callGetConnectionMysqlXADataSource();
        } catch (Exception ignored) {
        }

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String vendor = introspector.getJDBCVendor();
        Assert.assertEquals("Incorrect DB vendor", JDBCVendor.MYSQL, vendor);
    }

    @Test
    public void testGetConnectionMysqlXADataSource1() {
        try {
            callGetConnectionMysqlXADataSource1();
        } catch (Exception ignored) {
        }

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String vendor = introspector.getJDBCVendor();
        Assert.assertEquals("Incorrect DB vendor", JDBCVendor.MYSQL, vendor);
    }

    @Trace(dispatcher = true)
    private void callGetConnectionMysqlDataSource() throws SQLException {
        getConnection(new MysqlDataSource());
    }

    @Trace(dispatcher = true)
    private void callGetConnectionMysqlDataSource1() throws SQLException {
        getConnection1(new MysqlDataSource());
    }

    @Trace(dispatcher = true)
    private void callGetConnectionFabricMySQLDataSource() throws SQLException {
        getConnection(new FabricMySQLDataSource());
    }

    @Trace(dispatcher = true)
    private void callGetConnectionFabricMySQLDataSource1() throws SQLException {
        getConnection1(new FabricMySQLDataSource());
    }

    @Trace(dispatcher = true)
    private void callGetConnectionMysqlConnectionPoolDataSource() throws SQLException {
        getConnection(new MysqlConnectionPoolDataSource());
    }

    @Trace(dispatcher = true)
    private void callGetConnectionMysqlConnectionPoolDataSource1() throws SQLException {
        getConnection1(new MysqlConnectionPoolDataSource());
    }

    @Trace(dispatcher = true)
    private void callGetConnectionMysqlXADataSource() throws SQLException {
        getConnection(new MysqlXADataSource());
    }

    @Trace(dispatcher = true)
    private void callGetConnectionMysqlXADataSource1() throws SQLException {
        getConnection1(new MysqlXADataSource());
    }

    private void getConnection(MysqlDataSource baseDataSource) throws SQLException {
        baseDataSource.setURL(DB_CONNECTION);
        baseDataSource.setDatabaseName(DB_NAME);
        Connection conn = null;

        try {
            conn = baseDataSource.getConnection(DB_USER, DB_PASSWORD);
        } catch (Exception ignored) {
        } finally {
            if (conn!=null) {
                conn.close();
            }
        }
    }

    private void getConnection1(MysqlDataSource baseDataSource) throws SQLException {
        baseDataSource.setURL(DB_CONNECTION);
        baseDataSource.setDatabaseName(DB_NAME);
        baseDataSource.setUser(DB_USER);
        baseDataSource.setPassword(DB_PASSWORD);
        Connection conn = null;

        try {
            conn = baseDataSource.getConnection();
        } catch (Exception ignored) {
        } finally {
            if (conn!=null) {
                conn.close();
            }
        }
    }
}
