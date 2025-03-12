package com.nr.agent.security.instrumentation.tomcat7;

import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.api.agent.Trace;
import com.newrelic.api.agent.security.instrumentation.helpers.URLMappingsHelper;
import com.newrelic.api.agent.security.schema.ApplicationURLMapping;
import org.apache.catalina.servlets.DefaultServlet;
import org.junit.Assert;
import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = {"com.newrelic.agent.security.instrumentation.apache.tomcat7" })
public class APIEndpointTest {
    @ClassRule
    public static HttpServletServer server = new HttpServletServer();

    private final Map<String, String> expectedMappings = new HashMap<>();

    @Before
    public void setupEndpoints() {
        expectedMappings.put("/servlet/*", HttpServletServer.class.getName()+"$1");
        expectedMappings.put("/index.jsp", null);
        expectedMappings.put("/index.xhtml", null);
    }

    @Test
    public void testAPIEndpoint() throws Exception {
        service();

        Set<ApplicationURLMapping> mappings = URLMappingsHelper.getApplicationURLMappings();
        Assert.assertNotNull(mappings);
        Assert.assertEquals(3, mappings.size());
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

    @Trace(dispatcher = true)
    private void service() throws IOException, URISyntaxException {
        URL u = server.getEndPoint("/test").toURL();
        HttpURLConnection conn = (HttpURLConnection) u.openConnection();
        conn.setRequestProperty("content-type", "text/plain; charset=utf-8");
        conn.connect();
        conn.getResponseCode();
    }
}
