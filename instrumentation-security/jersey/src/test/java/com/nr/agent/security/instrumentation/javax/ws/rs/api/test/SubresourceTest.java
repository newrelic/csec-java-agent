package com.nr.agent.security.instrumentation.javax.ws.rs.api.test;

import com.newrelic.api.agent.security.instrumentation.helpers.URLMappingsHelper;
import com.newrelic.api.agent.security.schema.ApplicationURLMapping;
import com.nr.agent.security.instrumentation.javax.ws.rs.api.app.CustomerLocatorResource;
import com.nr.agent.security.instrumentation.javax.ws.rs.api.app.IdSubResource;
import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.api.agent.security.schema.AgentMetaData;
import com.nr.agent.security.instrumentation.javax.ws.rs.api.app.OrdersSubResource;
import com.nr.agent.security.instrumentation.javax.ws.rs.api.app.TestMapping;
import org.glassfish.jersey.client.HttpUrlConnectorProvider;
import org.glassfish.jersey.server.ResourceConfig;
import org.glassfish.jersey.test.JerseyTest;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;

import javax.ws.rs.client.Entity;
import javax.ws.rs.core.Application;
import javax.ws.rs.core.Response;
import java.util.Iterator;

@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = { "com.nr.instrumentation.security.jersey", "org.glassfish.jersey.server.internal" })
public class SubresourceTest extends JerseyTest {
    @BeforeClass
    public static void bringUp() {
        System.setProperty("jersey.config.test.container.port", "0");
    }

    @Test
    public void testAPIEndpoints() {
        target("/customers/orders/getStuff/1").request().get();

        Iterator<ApplicationURLMapping> mappings = URLMappingsHelper.getApplicationURLMappings().iterator();

        Assert.assertTrue(mappings.hasNext());
        assertMapping("/customers/orders/*", "*", CustomerLocatorResource.class.getName(), mappings.next());

        Assert.assertTrue(mappings.hasNext());
        assertMapping("/users/count", "GET", TestMapping.class.getName(), mappings.next());

        Assert.assertTrue(mappings.hasNext());
        assertMapping("/users", "PUT", TestMapping.class.getName(), mappings.next());

        Assert.assertTrue(mappings.hasNext());
        assertMapping("/users", "OPTIONS", TestMapping.class.getName(), mappings.next());

        Assert.assertTrue(mappings.hasNext());
        assertMapping("/users/count", "OPTIONS", TestMapping.class.getName(), mappings.next());
    }

    private void assertMapping(String path, String method, String handler, ApplicationURLMapping actualMapping){
        Assert.assertEquals(path, actualMapping.getPath());
        Assert.assertEquals(method, actualMapping.getMethod());
        Assert.assertEquals(handler, actualMapping.getHandler());
    }

    @Override
    protected Application configure() {
        return new ResourceConfig(CustomerLocatorResource.class, IdSubResource.class, OrdersSubResource.class, TestMapping.class);
    }
}
