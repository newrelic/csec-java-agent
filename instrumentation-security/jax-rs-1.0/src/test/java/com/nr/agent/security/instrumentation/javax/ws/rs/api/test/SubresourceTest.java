package com.nr.agent.security.instrumentation.javax.ws.rs.api.test;

import com.newrelic.security.test.marker.Java11IncompatibleTest;
import com.newrelic.security.test.marker.Java17IncompatibleTest;
import com.newrelic.security.test.marker.Java21IncompatibleTest;
import com.newrelic.security.test.marker.Java23IncompatibleTest;
import com.newrelic.security.test.marker.Java9IncompatibleTest;
import com.nr.agent.security.instrumentation.javax.ws.rs.api.app.CustomerLocatorResource;
import com.nr.agent.security.instrumentation.javax.ws.rs.api.app.IdSubResource;
import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.api.agent.security.schema.AgentMetaData;
import com.nr.agent.security.instrumentation.javax.ws.rs.api.app.OrdersSubResource;
import org.glassfish.jersey.client.HttpUrlConnectorProvider;
import org.glassfish.jersey.server.ResourceConfig;
import org.glassfish.jersey.test.JerseyTest;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runner.RunWith;

import javax.ws.rs.client.Entity;
import javax.ws.rs.core.Application;
import javax.ws.rs.core.Response;

@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = "com.newrelic.agent.security.instrumentation.javax.ws.rs.api")
@Category({ Java9IncompatibleTest.class, Java11IncompatibleTest.class, Java17IncompatibleTest.class, Java21IncompatibleTest.class, Java23IncompatibleTest.class })
public class SubresourceTest extends JerseyTest {
    @BeforeClass
    public static void bringUp() {
        System.setProperty("jersey.config.test.container.port", "0");
    }

    @Test
    public void testPost() {
        String postCustomer = "<customer>"
                + "<first-name>William</first-name>"
                + "</customer>";
        final Response response = target("/customers/orders/getStuff/post").request().post(Entity.entity(postCustomer, "application/json"));

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        AgentMetaData meta = introspector.getSecurityMetaData().getMetaData();

        
        Assert.assertNotNull("Service trace can not be empty/null.", meta.getServiceTrace());
        Assert.assertTrue("user level service method was not encountered.", meta.isUserLevelServiceMethodEncountered());
        Assert.assertTrue("Annotated userLevelService Method was not encountered.", meta.isFoundAnnotedUserLevelServiceMethod());
    }

    @Test
    public void testPath() {
        String postCustomer = "<customer>"
                + "<first-name>William</first-name>"
                + "</customer>";
        final Response response = target("/customers").path("orders").path("getStuff").path("post").request().post(Entity.entity(postCustomer,"application/json"));

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        AgentMetaData meta = introspector.getSecurityMetaData().getMetaData();


        Assert.assertNotNull("Service trace can not be empty/null.", meta.getServiceTrace());
        Assert.assertTrue("user level service method was not encountered.", meta.isUserLevelServiceMethodEncountered());
        Assert.assertTrue("Annotated userLevelService Method was not encountered.", meta.isFoundAnnotedUserLevelServiceMethod());
    }

    @Test
    public void testGet() {
        final Response response = target("customers/orders/getStuff/1").request().get(Response.class);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        AgentMetaData meta = introspector.getSecurityMetaData().getMetaData();

        
        Assert.assertNotNull("Service trace can not be empty/null.", meta.getServiceTrace());
        Assert.assertTrue("user level service method was not encountered.", meta.isUserLevelServiceMethodEncountered());
        Assert.assertTrue("Annotated userLevelService Method was not encountered.", meta.isFoundAnnotedUserLevelServiceMethod());
    }

    @Test
    public void testPut() {
        String putCustomer = "<customer>"
                + "<first-name>William</first-name>"
                + "</customer>";
        final Response response = target("customers/orders/getStuff/put").request().put(Entity.entity(putCustomer,"application/json"));

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        AgentMetaData meta = introspector.getSecurityMetaData().getMetaData();

        
        Assert.assertNotNull("Service trace can not be empty/null.", meta.getServiceTrace());
        Assert.assertTrue("user level service method was not encountered.", meta.isUserLevelServiceMethodEncountered());
        Assert.assertTrue("Annotated userLevelService Method was not encountered.", meta.isFoundAnnotedUserLevelServiceMethod());
    }

    @Test
    public void testDelete() {
        final Response response = target("customers/orders/getStuff/delete").request().delete();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        AgentMetaData meta = introspector.getSecurityMetaData().getMetaData();

        
        Assert.assertNotNull("Service trace can not be empty/null.", meta.getServiceTrace());
        Assert.assertTrue("user level service method was not encountered.", meta.isUserLevelServiceMethodEncountered());
        Assert.assertTrue("Annotated userLevelService Method was not encountered.", meta.isFoundAnnotedUserLevelServiceMethod());
    }

    @Test
    public void testHead() {
        final Response response = target("customers/orders/getStuff/head").request().head();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        AgentMetaData meta = introspector.getSecurityMetaData().getMetaData();

        
        Assert.assertNotNull("Service trace can not be empty/null.", meta.getServiceTrace());
        Assert.assertTrue("user level service method was not encountered.", meta.isUserLevelServiceMethodEncountered());
        Assert.assertTrue("Annotated userLevelService Method was not encountered.", meta.isFoundAnnotedUserLevelServiceMethod());
    }

    @Test
    public void testOptions() {
        final Response response = target("customers/orders/getStuff/options").request().options();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        AgentMetaData meta = introspector.getSecurityMetaData().getMetaData();

        
        Assert.assertNotNull("Service trace can not be empty/null.", meta.getServiceTrace());
        Assert.assertTrue("user level service method was not encountered.", meta.isUserLevelServiceMethodEncountered());
        Assert.assertTrue("Annotated userLevelService Method was not encountered.", meta.isFoundAnnotedUserLevelServiceMethod());
    }
    @Test
    public void testPatch() {
        String patchCustomer = "<customer>"
                + "<first-name>William</first-name>"
                + "</customer>";
        final Response response = target("customers/orders/getStuff/patch").request().property(HttpUrlConnectorProvider.SET_METHOD_WORKAROUND, true).method("PATCH",Entity.xml(patchCustomer));
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        AgentMetaData meta = introspector.getSecurityMetaData().getMetaData();

        
        Assert.assertNotNull("Service trace can not be empty/null.", meta.getServiceTrace());
        Assert.assertTrue("user level service method was not encountered.", meta.isUserLevelServiceMethodEncountered());
        Assert.assertTrue("Annotated userLevelService Method was not encountered.", meta.isFoundAnnotedUserLevelServiceMethod());
    }


    @Override
    protected Application configure() {
        return new ResourceConfig(CustomerLocatorResource.class, IdSubResource.class, OrdersSubResource.class);
    }
}
