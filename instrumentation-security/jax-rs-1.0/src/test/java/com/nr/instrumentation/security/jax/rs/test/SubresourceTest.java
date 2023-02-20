package com.nr.instrumentation.security.jax.rs.test;

import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.agent.security.introspec.internal.HttpServerRule;
import com.newrelic.api.agent.security.schema.AgentMetaData;
import com.nr.instrumentation.security.jax.rs.app.CustomerLocatorResource;
import com.nr.instrumentation.security.jax.rs.app.IdSubResource;
import com.nr.instrumentation.security.jax.rs.app.OrdersSubResource;
import org.glassfish.jersey.client.HttpUrlConnectorProvider;
import org.glassfish.jersey.server.ResourceConfig;
import org.glassfish.jersey.test.JerseyTest;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

import javax.ws.rs.client.Entity;
import javax.ws.rs.core.Application;
import javax.ws.rs.core.Response;

@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = "com.nr.instrumentation.javax.ws.rs.api")
public class SubresourceTest extends JerseyTest {


    @Test
    public void testPost() {
        String postCustomer = "<customer>"
                + "<first-name>William</first-name>"
                + "</customer>";
        final Response response = target("/customers/orders/getStuff/post").request().post(Entity.entity(postCustomer,"application/json"));

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        AgentMetaData meta = introspector.getSecurityMetaData().getMetaData();

        
        Assert.assertNotNull("Service trace can not be empty/null.", meta.getServiceTrace());
        Assert.assertTrue("user level service method was not encountered.", meta.isUserLevelServiceMethodEncountered());
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
    }

    @Test
    public void testGet() {
        final Response response = target("customers/orders/getStuff/1").request().get(Response.class);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        AgentMetaData meta = introspector.getSecurityMetaData().getMetaData();

        
        Assert.assertNotNull("Service trace can not be empty/null.", meta.getServiceTrace());
        Assert.assertTrue("user level service method was not encountered.", meta.isUserLevelServiceMethodEncountered());
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
    }

    @Test
    public void testDelete() {
        final Response response = target("customers/orders/getStuff/delete").request().delete();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        AgentMetaData meta = introspector.getSecurityMetaData().getMetaData();

        
        Assert.assertNotNull("Service trace can not be empty/null.", meta.getServiceTrace());
        Assert.assertTrue("user level service method was not encountered.", meta.isUserLevelServiceMethodEncountered());
    }

    @Test
    public void testHead() {
        final Response response = target("customers/orders/getStuff/head").request().head();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        AgentMetaData meta = introspector.getSecurityMetaData().getMetaData();

        
        Assert.assertNotNull("Service trace can not be empty/null.", meta.getServiceTrace());
        Assert.assertTrue("user level service method was not encountered.", meta.isUserLevelServiceMethodEncountered());
    }

    @Test
    public void testOptions() {
        final Response response = target("customers/orders/getStuff/options").request().options();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        AgentMetaData meta = introspector.getSecurityMetaData().getMetaData();

        
        Assert.assertNotNull("Service trace can not be empty/null.", meta.getServiceTrace());
        Assert.assertTrue("user level service method was not encountered.", meta.isUserLevelServiceMethodEncountered());
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
    }


    @Override
    protected Application configure() {
        return new ResourceConfig(CustomerLocatorResource.class, IdSubResource.class, OrdersSubResource.class);
    }
}
