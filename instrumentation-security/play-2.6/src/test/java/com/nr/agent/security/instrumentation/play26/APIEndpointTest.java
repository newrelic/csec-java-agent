/*
 *
 *  * Copyright 2022 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package com.nr.agent.security.instrumentation.play26;

import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.instrumentation.helpers.URLMappingsHelper;
import com.newrelic.api.agent.security.schema.ApplicationURLMapping;
import com.newrelic.api.agent.security.schema.SecurityMetaData;
import com.newrelic.security.test.marker.Java17IncompatibleTest;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runner.RunWith;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;


@Category({ Java17IncompatibleTest.class })
@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = { "com.newrelic.agent.security.instrumentation.play26" })
public class APIEndpointTest {

    @ClassRule
    public static PlayApplicationServerRule serverRule = new PlayApplicationServerRule();

    private static final Map<String, String> expectedMappings = new HashMap<>();

    @BeforeClass
    public static void setupMappings() {
        expectedMappings.put("/hello", SimpleJavaController.class.getName());
        expectedMappings.put("/scalaHello", SimpleScalaController.class.getName());
        expectedMappings.put("/post", SimpleJavaController.class.getName());
        expectedMappings.put("/index", SimpleJavaController.class.getName());
        expectedMappings.put("/simple", SimpleJavaController.class.getName());
    }

    @Test
    public void testControllerActions() throws IOException {
        HttpURLConnection conn = ((HttpURLConnection) serverRule.getEndpoint("/hello").openConnection());
        conn.connect();
        System.out.println(conn.getResponseCode());

        Set<ApplicationURLMapping> actualMappings = URLMappingsHelper.getApplicationURLMappings();
        Assert.assertNotNull(actualMappings);
        Assert.assertEquals(expectedMappings.size(), actualMappings.size());
        for (ApplicationURLMapping actualMapping : actualMappings) {
            assertMappings(actualMapping);
        }

        // verification of user-class entity
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        SecurityMetaData metaData = introspector.getSecurityMetaData();
        Assert.assertNotNull(metaData.getMetaData());
        Assert.assertTrue(metaData.getMetaData().isUserLevelServiceMethodEncountered());

        StackTraceElement element = metaData.getCustomAttribute(GenericHelper.USER_CLASS_ENTITY, StackTraceElement.class);
        Assert.assertNotNull(element);
        Assert.assertEquals(SimpleJavaController.class.getName(), element.getClassName());
        Assert.assertEquals("hello", element.getMethodName());
    }

    private void assertMappings(ApplicationURLMapping actualMapping){
        Assert.assertNotNull(actualMapping.getPath());
        Assert.assertNotNull(actualMapping.getHandler());
        Assert.assertNotNull(actualMapping.getMethod());

        String path = actualMapping.getPath();
        String handler = expectedMappings.get(path);
        String method = !path.equals("/post") ? "GET" : "POST";

        Assert.assertEquals(handler, actualMapping.getHandler());
        Assert.assertEquals(method, actualMapping.getMethod());
    }
}