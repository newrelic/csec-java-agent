package com.nr.agent.security.instrumentation.javax.ws.rs.api.test;

import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.api.agent.security.instrumentation.helpers.URLMappingsHelper;
import com.newrelic.api.agent.security.schema.ApplicationURLMapping;
import com.nr.agent.security.instrumentation.javax.ws.rs.api.app.CustomerLocatorResource;
import com.nr.agent.security.instrumentation.javax.ws.rs.api.app.IdSubResource;
import com.nr.agent.security.instrumentation.javax.ws.rs.api.app.OrdersSubResource;
import com.nr.agent.security.instrumentation.javax.ws.rs.api.app.TestMapping;
import org.glassfish.jersey.server.ResourceConfig;
import org.glassfish.jersey.test.JerseyTest;
import org.glassfish.jersey.test.grizzly.GrizzlyTestContainerFactory;
import org.glassfish.jersey.test.spi.TestContainerFactory;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;

import javax.ws.rs.core.Application;
import java.util.Set;

@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = { "com.newrelic.agent.security", "org.glassfish.jersey" })
public class SubresourceTest extends JerseyTest {
    @BeforeClass
    public static void bringUp() {
        System.setProperty("jersey.config.test.container.port", "0");
    }

    @Test
    public void testAPIEndpoints() {
        target("/customers/orders/getStuff/1").request().get();

        Set<ApplicationURLMapping> mappings = URLMappingsHelper.getApplicationURLMappings();
        Assert.assertEquals(5, mappings.size());

        Assert.assertTrue(mappings.contains(new ApplicationURLMapping("*", "/customers/orders/*", CustomerLocatorResource.class.getName())));
        Assert.assertTrue(mappings.contains(new ApplicationURLMapping("GET","/users/count", TestMapping.class.getName())));
        Assert.assertTrue(mappings.contains(new ApplicationURLMapping("PUT","/users", TestMapping.class.getName())));
        Assert.assertTrue(mappings.contains(new ApplicationURLMapping("OPTIONS","/users", TestMapping.class.getName())));
        Assert.assertTrue(mappings.contains(new ApplicationURLMapping("OPTIONS", "/users/count", TestMapping.class.getName())));
    }

    @Override
    protected Application configure() {
        return new ResourceConfig(CustomerLocatorResource.class, IdSubResource.class, OrdersSubResource.class, TestMapping.class);
    }

    @Override
    protected TestContainerFactory getTestContainerFactory() {
        return new GrizzlyTestContainerFactory();
    }
}
