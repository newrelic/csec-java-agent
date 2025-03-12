package com.nr.agent.security.instrumentation.servlet5;

import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.api.agent.security.instrumentation.helpers.URLMappingsHelper;
import com.newrelic.api.agent.security.schema.ApplicationURLMapping;
import org.junit.Assert;
import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = { "jakarta.servlet", "com.newrelic.agent.security.instrumentation.servlet5" })
public class ServletContainerInitializerTest {

    @ClassRule
    public static HttpServletServer server = new HttpServletServer();

    private final Map<String, String> expectedMappings = new HashMap<>();

    @Before
    public void setupEndpoints() {
        expectedMappings.put("/*", "com.nr.agent.security.instrumentation.servlet5.HttpTestServlet");
        expectedMappings.put("/test", "com.nr.agent.security.instrumentation.servlet5.HttpTestServlet");
        expectedMappings.put("/index.jsp", null);
        expectedMappings.put("/index.xhtml", null);
    }

    @Test
    public void testURLMappings() {
        Set<ApplicationURLMapping> mappings = URLMappingsHelper.getApplicationURLMappings();
        Assert.assertNotNull(mappings);
        Assert.assertEquals(4, mappings.size());
        for (ApplicationURLMapping mapping : mappings) {
            assertMappings(mapping);
        }
    }

    private void assertMappings(ApplicationURLMapping actualMapping) {
        Assert.assertNotNull(actualMapping);

        Assert.assertNotNull(actualMapping.getPath());
        String path = actualMapping.getPath();
        String handler = expectedMappings.get(path);

        Assert.assertNotNull(actualMapping.getMethod());

        Assert.assertEquals(handler, actualMapping.getHandler());
        Assert.assertEquals("*", actualMapping.getMethod());
    }
}
