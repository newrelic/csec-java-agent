/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package com.newrelic.agent.security.instrumentation.jdbc.mariadb130;

import ch.vorburger.mariadb4j.DB;
import ch.vorburger.mariadb4j.DBConfigurationBuilder;
import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.api.agent.security.schema.JDBCVendor;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = {"org.mariadb.jdbc"})
public class MariaDb130Test {

    private static DB mariaDb;

    private static String connectionString;
    private static String dbName;

    private static Connection connection;

    private static List<String> QUERIES = new ArrayList<>();

    @BeforeClass
    public static void setUpDb() throws Exception {
        QUERIES.add("select * from testQuery");
        DBConfigurationBuilder builder = DBConfigurationBuilder.newBuilder()
                .setPort(0); // This will automatically find a free port

        dbName = "MariaDB" + System.currentTimeMillis();
        mariaDb = DB.newEmbeddedDB(builder.build());
        connectionString = builder.getURL(dbName);
        mariaDb.start();

        mariaDb.createDB(dbName);
        mariaDb.source("maria-db-test.sql", null, null, dbName);
    }
    @AfterClass
    public static void tearDownDb() throws Exception {
        mariaDb.stop();
    }

    @Test
    public void testConnect() throws SQLException, ClassNotFoundException {
        Class.forName("org.mariadb.jdbc.Driver");
        connection = DriverManager.getConnection(connectionString, "root", "");

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String vendor = introspector.getJDBCVendor();
        Assert.assertEquals("Incorrect DB vendor", vendor, JDBCVendor.MARIA_DB);
    }
}
