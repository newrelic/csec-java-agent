package com.nr.instrumentation.security.servlet24;

import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.api.agent.Trace;
import com.newrelic.api.agent.security.schema.AgentMetaData;
import com.nr.instrumentation.security.HttpServletServer;
import org.junit.Assert;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URISyntaxException;
import java.net.URL;

@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = { "javax.servlet" })
public class WebServletTest {
    @ClassRule
    public static HttpServletServer server = new HttpServletServer();

    @Test
    public void testAnnotation() throws Exception {
        webServletAnnotation();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        AgentMetaData metaData = introspector.getSecurityMetaData().getMetaData();
        Assert.assertTrue(metaData.isUserLevelServiceMethodEncountered());
        Assert.assertNotNull(metaData.getServiceTrace());
    }

    @Trace(dispatcher = true)
    private void webServletAnnotation() throws IOException, URISyntaxException {
        URL u = server.getEndPoint("").toURL();
        HttpURLConnection conn = (HttpURLConnection) u.openConnection();
        conn.setRequestProperty("content-type", "text/plain; charset=utf-8");
        conn.setRequestMethod("GET");
        conn.connect();
        conn.getResponseCode();
    }
}
