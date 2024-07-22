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
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.Iterator;
import java.util.Set;

@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = "com.newrelic.agent.java.security.cxf.jaxrs")
public class APIEndpointTest {
    private static Server myServer;

    @BeforeClass
    public static void startServer() {
        int port = SecurityInstrumentationTestRunner.getIntrospector().getRandomPort();
        JAXRSServerFactoryBean sf = new JAXRSServerFactoryBean();

        sf.setResourceClasses(CustomerLocatorResource.class, TestMapping.class);
        sf.setResourceProvider(CustomerLocatorResource.class, new SingletonResourceProvider(new CustomerLocatorResource()));
        sf.setBindingFactory(new JAXRSBindingFactory());

        sf.setAddress("http://localhost:" + port);
        myServer = sf.create();
        myServer.start();
    }

    @AfterClass
    public static void stopServer() {
        myServer.stop();
    }

    private final String handler = TestMapping.class.getName();

    @Test
    public void testAPIEndpoint() {
        Set<ApplicationURLMapping> mappings = URLMappingsHelper.getApplicationURLMappings();
        Assert.assertEquals(5, mappings.size());

        Iterator<ApplicationURLMapping> mapping = mappings.iterator();
        String path = "/users";

        while (mapping.hasNext()){
            ApplicationURLMapping urlMapping = mapping.next();
            if (urlMapping.getPath().equals("/customers/orders/*")){
                assertMapping("*", "/customers/orders/*", CustomerLocatorResource.class.getName(), urlMapping);
            } else if (urlMapping.getPath().equals(path +"/count")){
                assertMapping("GET", path +"/count", handler, urlMapping);
            } else {
                assertMapping(urlMapping.getMethod(), path, handler, urlMapping);
            }
        }
    }

    private void assertMapping(String method, String path, String handler, ApplicationURLMapping actualMapping) {
        Assert.assertEquals(method, actualMapping.getMethod());
        Assert.assertEquals(path, actualMapping.getPath());
        Assert.assertEquals(handler, actualMapping.getHandler());
    }
}
