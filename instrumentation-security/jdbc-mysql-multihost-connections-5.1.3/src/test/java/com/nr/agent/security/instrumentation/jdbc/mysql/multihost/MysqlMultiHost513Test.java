package com.nr.agent.security.instrumentation.jdbc.mysql.multihost;

import com.mysql.fabric.jdbc.FabricMySQLDataSource;
import com.mysql.jdbc.jdbc2.optional.MysqlConnectionPoolDataSource;
import com.mysql.jdbc.jdbc2.optional.MysqlDataSource;
import com.mysql.jdbc.jdbc2.optional.MysqlXADataSource;
import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.api.agent.Trace;
import com.newrelic.api.agent.security.schema.JDBCVendor;
import com.wix.mysql.EmbeddedMysql;
import com.wix.mysql.ScriptResolver;
import com.wix.mysql.config.Charset;
import com.wix.mysql.config.MysqldConfig;
import com.wix.mysql.distribution.Version;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.Properties;
import java.util.concurrent.TimeUnit;

@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = {"com.mysql.jdbc"})
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class MysqlMultiHost513Test {
    private static final String DB_USER = "";
    private static final String DB_PASSWORD = "";
    private static String DB_CONNECTION;
    private static String DB_NAME = "test";
    private static EmbeddedMysql mysqld = null;

    @BeforeClass
    public static void setUpDb() throws Exception {
        MysqldConfig config = MysqldConfig.aMysqldConfig(Version.v5_7_latest)
                .withCharset(Charset.UTF8)
                .withFreePort()
                .withTimeout(2, TimeUnit.MINUTES)
                .withUser(DB_USER, DB_PASSWORD)
                .build();

        mysqld = EmbeddedMysql.anEmbeddedMysql(config)
                .addSchema(DB_NAME, ScriptResolver.classPathScript("maria-db-test.sql"))
                .start();

        DB_CONNECTION = "jdbc:mysql:loadbalance://localhost:" + mysqld.getConfig().getPort() + "/" + DB_NAME + "?useSSL=false";
    }

    @AfterClass
    public static void tearDownDb() throws Exception {
        if (mysqld!=null) {
            mysqld.stop();
        }
    }

    @Test
    public void testConnect() throws SQLException {
        getConnection();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String vendor = introspector.getJDBCVendor();
        Assert.assertEquals("Incorrect DB vendor", JDBCVendor.MYSQL, vendor);
    }

    @Test
    public void testConnect1() throws SQLException {
        getConnection1();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String vendor = introspector.getJDBCVendor();
        Assert.assertEquals("Incorrect DB vendor", JDBCVendor.MYSQL, vendor);
    }

    @Test
    public void testConnect2() throws SQLException {
        getConnection2();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String vendor = introspector.getJDBCVendor();
        Assert.assertEquals("Incorrect DB vendor", JDBCVendor.MYSQL, vendor);
    }

    @Test
    public void testConnect3() throws SQLException, ClassNotFoundException {
        Class.forName("com.mysql.jdbc.Driver");
        DriverManager.getConnection(DB_CONNECTION, DB_USER, DB_PASSWORD);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String vendor = introspector.getJDBCVendor();
        Assert.assertEquals("Incorrect DB vendor", JDBCVendor.MYSQL, vendor);
    }

    @Trace(dispatcher = true)
    private void getConnection() throws SQLException {
        Connection dbConnection = null;

        try {
            Class.forName("com.mysql.jdbc.Driver");
            dbConnection = DriverManager.getConnection(DB_CONNECTION, DB_USER, DB_PASSWORD);
        } catch (Exception ignored) {
        }
        finally {
            if (dbConnection!=null) {
                dbConnection.close();
            }
        }
    }

    @Trace(dispatcher = true)
    private void getConnection1() throws SQLException {
        Connection dbConnection = null;

        try {
            Properties info = new Properties();
            info.put("user", DB_USER);
            info.put("password", DB_PASSWORD);
            Class.forName("com.mysql.jdbc.Driver");
            dbConnection = DriverManager.getConnection(DB_CONNECTION, info);
        } catch (Exception ignored) {
        }
        finally {
            if (dbConnection!=null) {
                dbConnection.close();
            }
        }
    }

    @Trace(dispatcher = true)
    private void getConnection2() throws SQLException {
        Connection dbConnection = null;

        try {
            Class.forName("com.mysql.jdbc.Driver");
            dbConnection = DriverManager.getConnection(DB_CONNECTION);
        } catch (Exception ignored) {
        }
        finally {
            if (dbConnection!=null) {
                dbConnection.close();
            }
        }
    }

//    @Trace(dispatcher = true)
//    private void getConnection3() throws SQLException {
//        Connection dbConnection = null;
//
//        try {
//            Class.forName("com.mysql.jdbc.Driver");
//            dbConnection = ConnectionImpl.getInstance(new ConnectionString(DB_CONNECTION, new Properties()), "localhost", mysqld.getConfig().getPort(), new Properties());
//        } catch (Exception ignored) {
//        }
//        finally {
//            if (dbConnection!=null) {
//                dbConnection.close();
//            }
//        }
//    }

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

//    @Test
//    public void testGetConnectionFabricMySQLDataSource() {
//        try {
//            callGetConnectionFabricMySQLDataSource();
//        } catch (Exception ignored) {
//        }
//
//        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
//        String vendor = introspector.getJDBCVendor();
//        Assert.assertEquals("Incorrect DB vendor", JDBCVendor.MYSQL, vendor);
//    }
//
//    @Test
//    public void testGetConnectionFabricMySQLDataSource1() {
//        try {
//            callGetConnectionFabricMySQLDataSource1();
//        } catch (Exception ignored) {
//        }
//
//        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
//        String vendor = introspector.getJDBCVendor();
//        Assert.assertEquals("Incorrect DB vendor", JDBCVendor.MYSQL, vendor);
//    }

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
            System.out.println(ignored);
            ignored.printStackTrace();
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
