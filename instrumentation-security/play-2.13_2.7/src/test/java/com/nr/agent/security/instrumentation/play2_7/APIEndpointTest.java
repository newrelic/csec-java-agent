/*
 *
 *  * Copyright 2022 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package com.nr.agent.security.instrumentation.play2_7;

import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.instrumentation.helpers.URLMappingsHelper;
import com.newrelic.api.agent.security.schema.ApplicationURLMapping;
import com.newrelic.api.agent.security.schema.Framework;
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
@InstrumentationTestConfig(includePrefixes = { "com.newrelic.agent.security.instrumentation.play2_13" })
public class APIEndpointTest {

    @ClassRule
    public static PlayApplicationServerRule serverRule = new PlayApplicationServerRule();

    private static final Map<String, String> expectedMappings = new HashMap<>();

    @BeforeClass
    public static void setupMappings() {
        expectedMappings.put("/hello", SimpleJavaController.class.getName() + ".hello");
        expectedMappings.put("/scalaHello", SimpleScalaController.class.getName() + ".scalaHello");
        expectedMappings.put("/post/$data<[^/]+>", SimpleJavaController.class.getName() + ".post(data:String)");
        expectedMappings.put("/post1/$data<[a-zA-Z]+>", SimpleJavaController.class.getName() + ".post(data:String)");
        expectedMappings.put("/index", SimpleJavaController.class.getName() + ".index");
        expectedMappings.put("/simple", SimpleJavaController.class.getName() + ".simple");
    }

    @Test
    public void testControllerActions() throws IOException {
        makeRequest("/hello");

        Set<ApplicationURLMapping> actualMappings = URLMappingsHelper.getApplicationURLMappings();
        Assert.assertNotNull(actualMappings);
        Assert.assertEquals(expectedMappings.size(), actualMappings.size());
        for (ApplicationURLMapping actualMapping : actualMappings) {
            assertMappings(actualMapping);
        }

        // verification of user-class entity
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        SecurityMetaData metaData = introspector.getSecurityMetaData();
        verifyUserClassDetection(metaData, "hello");

        // verification of route detection
        Assert.assertEquals("/hello", metaData.getRequest().getRoute());
        Assert.assertEquals(Framework.PLAY.name(), metaData.getMetaData().getFramework());
    }

    @Test
    public void testRouteDetection() throws IOException {
        makeRequest("/post/data");

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        SecurityMetaData metaData = introspector.getSecurityMetaData();

        verifyUserClassDetection(metaData, "post");
        Assert.assertEquals("/post/$data<[^/]+>", metaData.getRequest().getRoute());
        Assert.assertEquals(Framework.PLAY.name(), metaData.getMetaData().getFramework());
    }

    @Test
    public void testRouteDetection1() throws IOException {
        makeRequest("/post1/data");

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        SecurityMetaData metaData = introspector.getSecurityMetaData();

        verifyUserClassDetection(metaData, "post");
        Assert.assertEquals("/post1/$data<[a-zA-Z]+>", metaData.getRequest().getRoute());
        Assert.assertEquals(Framework.PLAY.name(), metaData.getMetaData().getFramework());
    }

    private void makeRequest(String path) throws IOException {
        HttpURLConnection conn = ((HttpURLConnection) serverRule.getEndpoint(path).openConnection());
        conn.connect();
        System.out.println(conn.getResponseCode());
    }

    private void verifyUserClassDetection(SecurityMetaData metaData, String methodName) {
        Assert.assertNotNull(metaData.getMetaData());
        Assert.assertTrue(metaData.getMetaData().isUserLevelServiceMethodEncountered());

        StackTraceElement element = metaData.getCustomAttribute(GenericHelper.USER_CLASS_ENTITY, StackTraceElement.class);
        Assert.assertNotNull(element);
        Assert.assertEquals(SimpleJavaController.class.getName(), element.getClassName());
        Assert.assertEquals(methodName, element.getMethodName());
    }
    private void assertMappings(ApplicationURLMapping actualMapping){
        Assert.assertNotNull(actualMapping.getPath());
        Assert.assertNotNull(actualMapping.getHandler());
        Assert.assertNotNull(actualMapping.getMethod());

        String path = actualMapping.getPath();
        String handler = expectedMappings.get(path);
        String method = "GET";

        Assert.assertEquals(handler, actualMapping.getHandler());
        Assert.assertEquals(method, actualMapping.getMethod());
    }
}