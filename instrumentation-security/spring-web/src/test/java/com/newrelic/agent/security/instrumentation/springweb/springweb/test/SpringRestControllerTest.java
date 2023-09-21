package com.newrelic.agent.security.instrumentation.springweb.springweb.test;/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.api.agent.security.schema.AgentMetaData;
import com.newrelic.agent.security.instrumentation.springweb.springweb.app.App;
import org.junit.Assert;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;

@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = { "com.nr.agent.instrumentation" })
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class SpringRestControllerTest {

    @Test
    public void testRequestMapping() {
        Assert.assertEquals("From Request RestMapping", App.requestMappingWithRest());

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
//        String expectedTransactionName = "OtherTransaction/SpringController/errorPath (GET)";
        AgentMetaData meta = introspector.getSecurityMetaData().getMetaData();
        Assert.assertNotNull("Service trace can not be empty/null.", meta.getServiceTrace());
        Assert.assertTrue("user level service method was not encountered.", meta.isUserLevelServiceMethodEncountered());
    }

    @Test
    public void testGetMapping() {
        Assert.assertEquals("From Get RestMapping", App.getMappingWithRest());

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        AgentMetaData meta = introspector.getSecurityMetaData().getMetaData();
        Assert.assertNotNull("Service trace can not be empty/null.", meta.getServiceTrace());
        Assert.assertTrue("user level service method was not encountered.", meta.isUserLevelServiceMethodEncountered());
    }

    @Test
    public void testPostMapping() {
        Assert.assertEquals("From Post RestMapping", App.postMappingWithRest());

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        AgentMetaData meta = introspector.getSecurityMetaData().getMetaData();
        Assert.assertNotNull("Service trace can not be empty/null.", meta.getServiceTrace());
        Assert.assertTrue("user level service method was not encountered.", meta.isUserLevelServiceMethodEncountered());
    }

    @Test
    public void testPatchMapping() {
        Assert.assertEquals("From Patch RestMapping", App.patchMappingWithRest());

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        AgentMetaData meta = introspector.getSecurityMetaData().getMetaData();
        Assert.assertNotNull("Service trace can not be empty/null.", meta.getServiceTrace());
        Assert.assertTrue("user level service method was not encountered.", meta.isUserLevelServiceMethodEncountered());
    }

    @Test
    public void testPutMapping() {
        Assert.assertEquals("From Put RestMapping", App.putMappingWithRest());

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        AgentMetaData meta = introspector.getSecurityMetaData().getMetaData();
        Assert.assertNotNull("Service trace can not be empty/null.", meta.getServiceTrace());
        Assert.assertTrue("user level service method was not encountered.", meta.isUserLevelServiceMethodEncountered());
    }

    @Test
    public void testDeleteMapping() {
        Assert.assertEquals("From Delete RestMapping", App.deleteMappingWithRest());

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        AgentMetaData meta = introspector.getSecurityMetaData().getMetaData();
        Assert.assertNotNull("Service trace can not be empty/null.", meta.getServiceTrace());
        Assert.assertTrue("user level service method was not encountered.", meta.isUserLevelServiceMethodEncountered());
    }
}
