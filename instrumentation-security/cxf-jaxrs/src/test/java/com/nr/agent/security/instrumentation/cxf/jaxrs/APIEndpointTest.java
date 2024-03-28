package com.nr.agent.security.instrumentation.cxf.jaxrs;

import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.api.agent.security.instrumentation.helpers.URLMappingsHelper;
import com.newrelic.api.agent.security.schema.ApplicationURLMapping;
import com.nr.agent.security.instrumentation.cxf.jaxrs.app.CustomerLocatorResource;
import com.nr.agent.security.instrumentation.cxf.jaxrs.app.TestMapping;
import org.apache.cxf.endpoint.Server;
import org.apache.cxf.jaxrs.JAXRSBindingFactory;
import org.apache.cxf.jaxrs.JAXRSServerFactoryBean;
import org.apache.cxf.jaxrs.lifecycle.SingletonResourceProvider;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.IOException;
import java.net.ServerSocket;
import java.util.Iterator;
import java.util.Set;

@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = "com.newrelic.agent.java.security.cxf.jaxrs")
public class APIEndpointTest {
    private final String handler = TestMapping.class.getName();

    @Test
    public void testAPIEndpoint() {
        startServer();

        Set<ApplicationURLMapping> mappings = URLMappingsHelper.getApplicationURLMappings();
        Assert.assertEquals(5, mappings.size());

        Iterator<ApplicationURLMapping> mapping = mappings.iterator();
        String path = "/users/";

        Assert.assertTrue(mapping.hasNext());
        assertMapping("*", "/customers/orders/*", CustomerLocatorResource.class.getName(), mapping.next());

        Assert.assertTrue(mapping.hasNext());
        assertMapping("POST", path, handler, mapping.next());

        Assert.assertTrue(mapping.hasNext());
        assertMapping("GET", path, handler, mapping.next());

        Assert.assertTrue(mapping.hasNext());
        assertMapping("PUT", path, handler, mapping.next());

        Assert.assertTrue(mapping.hasNext());
        assertMapping("GET", path +"count", handler, mapping.next());

    }

    private void assertMapping(String method, String path, String handler, ApplicationURLMapping actualMapping) {
        Assert.assertEquals(method, actualMapping.getMethod());
        Assert.assertEquals(path, actualMapping.getPath());
        Assert.assertEquals(handler, actualMapping.getHandler());
    }

    private void startServer() {
        JAXRSServerFactoryBean sf = new JAXRSServerFactoryBean();

        sf.setResourceClasses(CustomerLocatorResource.class, TestMapping.class);

        sf.setBindingFactory(new JAXRSBindingFactory());

        sf.setAddress("http://localhost:" + getRandomPort());
        Server myServer = sf.create();
        myServer.start();
    }

    private int getRandomPort() {
        try (ServerSocket socket = new ServerSocket(0)){
            return socket.getLocalPort();
        } catch (IOException e) {
            throw new RuntimeException("Unable to allocate ephemeral port");
        }
    }
}
