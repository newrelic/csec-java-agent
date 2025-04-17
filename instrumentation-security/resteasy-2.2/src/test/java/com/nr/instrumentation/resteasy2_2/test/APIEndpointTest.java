package com.nr.instrumentation.resteasy2_2.test;

import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.api.agent.Trace;
import com.newrelic.api.agent.security.instrumentation.helpers.URLMappingsHelper;
import com.newrelic.api.agent.security.schema.ApplicationURLMapping;
import com.newrelic.security.test.marker.*;
import com.nr.instrumentation.resteasy2_2.app.CustomerLocatorResource;
import com.nr.instrumentation.resteasy2_2.app.TestMapping;
import org.apache.catalina.LifecycleException;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runner.RunWith;

import java.io.IOException;
import java.lang.instrument.UnmodifiableClassException;
import java.net.HttpURLConnection;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = {"com.newrelic.agent.security.instrumentation.resteasy2", "org.jboss.resteasy.core.registry"})
@Category({ Java9IncompatibleTest.class, Java11IncompatibleTest.class, Java17IncompatibleTest.class, Java21IncompatibleTest.class, Java23IncompatibleTest.class })
public class APIEndpointTest {

    private final String handler = TestMapping.class.getName();
    private static final String path = "/users";
    private static final Map<String, String> mappings = new HashMap<>();

    @BeforeClass
    public static void startServer() throws LifecycleException, UnmodifiableClassException, ClassNotFoundException {
        SecurityInstrumentationTestRunner.instrumentation.retransformClasses(Class.forName("org.jboss.resteasy.logging.Logger"));
        TestApplication.startServer();
        mappings.put(path, "GET");
        mappings.put(path +"/count", "GET");
        mappings.put("/customers/orders/*", "*");
    }

    @AfterClass
    public static void stopServer() {
        TestApplication.stopServer();
    }

    @Test
    public void testURLMappings() throws IOException {
        service();
        Set<ApplicationURLMapping> mappings = URLMappingsHelper.getApplicationURLMappings();

        Assert.assertEquals(3, mappings.size());

        for (ApplicationURLMapping applicationURLMapping : mappings) {
            assertMapping(applicationURLMapping);
        }
    }

    private void assertMapping(ApplicationURLMapping actualMapping) {
        Assert.assertNotNull(actualMapping.getMethod());
        Assert.assertNotNull(actualMapping.getPath());
        Assert.assertEquals(mappings.get(actualMapping.getPath()), actualMapping.getMethod());
        if (actualMapping.getMethod().equals("*")){
            Assert.assertEquals(CustomerLocatorResource.class.getName(), actualMapping.getHandler());
        } else {
            Assert.assertEquals(handler, actualMapping.getHandler());
        }
    }

    @Trace(dispatcher = true)
    private void service() throws IOException {
        HttpURLConnection conn = (HttpURLConnection) TestApplication.getEndPoint("users").openConnection();
        conn.connect();
        conn.getResponseCode();
    }
}
