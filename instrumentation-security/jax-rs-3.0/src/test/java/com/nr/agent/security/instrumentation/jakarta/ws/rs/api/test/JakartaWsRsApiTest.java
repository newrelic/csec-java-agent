package com.nr.agent.security.instrumentation.jakarta.ws.rs.api.test;

import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.api.agent.security.schema.AgentMetaData;
import com.nr.agent.security.instrumentation.jakarta.ws.rs.api.app.App;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = "com.newrelic.agent.security.instrumentation.jakarta.ws.rs.api")
public class JakartaWsRsApiTest {
    @Test
    public void testPut()  {
        Assert.assertEquals("Put it!", App.callPut());

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        AgentMetaData meta = introspector.getSecurityMetaData().getMetaData();
        
        Assert.assertNotNull("Service trace can not be empty/null.", meta.getServiceTrace());
        Assert.assertTrue("user level service method was not encountered.", meta.isUserLevelServiceMethodEncountered());
        Assert.assertTrue("Annotated userLevelService Method was not encountered.", meta.isFoundAnnotedUserLevelServiceMethod());
    }
    @Test
    public void testPost()  {
        Assert.assertEquals("Post it!", App.callPost());

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        AgentMetaData meta = introspector.getSecurityMetaData().getMetaData();

        Assert.assertNotNull("Service trace can not be empty/null.", meta.getServiceTrace());
        Assert.assertTrue("user level service method was not encountered.", meta.isUserLevelServiceMethodEncountered());
        Assert.assertTrue("Annotated userLevelService Method was not encountered.", meta.isFoundAnnotedUserLevelServiceMethod());
    }
    @Test
    public void testGet()  {
        Assert.assertEquals("Get it!", App.callGet());

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        AgentMetaData meta = introspector.getSecurityMetaData().getMetaData();
        
        Assert.assertNotNull("Service trace can not be empty/null.", meta.getServiceTrace());
        Assert.assertTrue("user level service method was not encountered.", meta.isUserLevelServiceMethodEncountered());
        Assert.assertTrue("Annotated userLevelService Method was not encountered.", meta.isFoundAnnotedUserLevelServiceMethod());
    }
    @Test
    public void testDelete()  {
        Assert.assertEquals("Delete it!", App.callDelete());

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        AgentMetaData meta = introspector.getSecurityMetaData().getMetaData();

        Assert.assertNotNull("Service trace can not be empty/null.", meta.getServiceTrace());
        Assert.assertTrue("user level service method was not encountered.", meta.isUserLevelServiceMethodEncountered());
        Assert.assertTrue("Annotated userLevelService Method was not encountered.", meta.isFoundAnnotedUserLevelServiceMethod());
    }
    @Test
    public void testHead()  {
        Assert.assertEquals("Head it!", App.callHead());

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        AgentMetaData meta = introspector.getSecurityMetaData().getMetaData();

        Assert.assertNotNull("Service trace can not be empty/null.", meta.getServiceTrace());
        Assert.assertTrue("user level service method was not encountered.", meta.isUserLevelServiceMethodEncountered());
        Assert.assertTrue("Annotated userLevelService Method was not encountered.", meta.isFoundAnnotedUserLevelServiceMethod());
    }
    @Test
    public void testOptions()  {
        Assert.assertEquals("Options it!", App.callOption());

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        AgentMetaData meta = introspector.getSecurityMetaData().getMetaData();

        Assert.assertNotNull("Service trace can not be empty/null.", meta.getServiceTrace());
        Assert.assertTrue("user level service method was not encountered.", meta.isUserLevelServiceMethodEncountered());
        Assert.assertTrue("Annotated userLevelService Method was not encountered.", meta.isFoundAnnotedUserLevelServiceMethod());
    }
    @Test
    public void testPatch()  {
        Assert.assertEquals("Patch it!", App.callPatch());

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        AgentMetaData meta = introspector.getSecurityMetaData().getMetaData();

        Assert.assertNotNull("Service trace can not be empty/null.", meta.getServiceTrace());
        Assert.assertTrue("user level service method was not encountered.", meta.isUserLevelServiceMethodEncountered());
        Assert.assertTrue("Annotated userLevelService Method was not encountered.", meta.isFoundAnnotedUserLevelServiceMethod());
    }
    @Test
    public void testPath() {
        Assert.assertEquals("path it!", App.callPath());

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        AgentMetaData meta = introspector.getSecurityMetaData().getMetaData();

        Assert.assertNotNull("Service trace can not be empty/null.", meta.getServiceTrace());
        Assert.assertTrue("user level service method was not encountered.", meta.isUserLevelServiceMethodEncountered());
        Assert.assertTrue("Annotated userLevelService Method was not encountered.", meta.isFoundAnnotedUserLevelServiceMethod());
    }
}
