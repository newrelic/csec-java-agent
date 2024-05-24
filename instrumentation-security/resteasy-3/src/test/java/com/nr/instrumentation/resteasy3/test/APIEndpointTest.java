package com.nr.instrumentation.resteasy3.test;

import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.api.agent.Trace;
import com.newrelic.api.agent.security.instrumentation.helpers.URLMappingsHelper;
import com.newrelic.api.agent.security.schema.ApplicationURLMapping;
import com.nr.instrumentation.resteasy3.app.CustomerLocatorResource;
import com.nr.instrumentation.resteasy3.app.TestMapping;
import org.apache.catalina.LifecycleException;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.IOException;
import java.lang.instrument.UnmodifiableClassException;
import java.net.HttpURLConnection;
import java.util.Iterator;
import java.util.Set;

@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = {"com.newrelic.agent.security.instrumentation.resteasy3", "org.jboss.resteasy.core.registry"})
public class APIEndpointTest {
    private final String handler = TestMapping.class.getName();
    private final String path = "/users";

    @BeforeClass
    public static void startServer() throws LifecycleException, UnmodifiableClassException, ClassNotFoundException {
        SecurityInstrumentationTestRunner.instrumentation.retransformClasses(Class.forName("org.jboss.resteasy.logging.Logger"));
        TestApplication.startServer();
    }

    @AfterClass
    public static void stopServer() {
        TestApplication.stopServer();
    }

    @Test
    public void testURLMappings() throws IOException {
        service();
        Set<ApplicationURLMapping> mappings = URLMappingsHelper.getApplicationURLMappings();

        Assert.assertEquals(4, mappings.size());

        Iterator<ApplicationURLMapping> mapping = mappings.iterator();

        Assert.assertTrue(mapping.hasNext());
        assertMapping("*", "/customers/orders/*", CustomerLocatorResource.class.getName(), mapping.next());

        Assert.assertTrue(mapping.hasNext());
        assertMapping("GET", path, handler, mapping.next());

        Assert.assertTrue(mapping.hasNext());
        assertMapping("GET", path +"/count", handler, mapping.next());

        Assert.assertTrue(mapping.hasNext());
        assertMapping("PUT", path, handler, mapping.next());
    }

    private void assertMapping(String method, String path, String handler, ApplicationURLMapping actualMapping) {
        Assert.assertEquals(method, actualMapping.getMethod());
        Assert.assertEquals(path, actualMapping.getPath());
        Assert.assertEquals(handler, actualMapping.getHandler());
    }

    @Trace(dispatcher = true)
    private void service() throws IOException {
        HttpURLConnection conn = (HttpURLConnection)TestApplication.getEndPoint("users/count/9").openConnection();
        conn.connect();
        conn.getResponseCode();
    }
}
