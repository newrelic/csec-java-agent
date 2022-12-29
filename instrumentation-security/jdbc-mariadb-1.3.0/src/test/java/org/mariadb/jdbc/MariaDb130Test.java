/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package org.mariadb.jdbc;

import ch.vorburger.mariadb4j.DB;
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

@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = {"org.mariadb.jdbc"})
public class MariaDb130Test {

    public static DB database;

    @BeforeClass
    public static void setUpDb() throws Exception {
        database = DB.newEmbeddedDB(3306);
        database.start();
    }

    @AfterClass
    public static void tearDownDb() throws Exception {
        database.stop();
    }

    @Test
    public void testConnect() throws SQLException {
        Connection connection = DriverManager.getConnection("jdbc:mysql://localhost/test", "root", "");

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        String vendor = introspector.getJDBCVendor();
        Assert.assertEquals("Incorrect DB vendor", vendor, JDBCVendor.MARIA_DB);
    }
}
