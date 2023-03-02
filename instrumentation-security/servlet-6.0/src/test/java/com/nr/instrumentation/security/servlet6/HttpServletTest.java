package com.nr.instrumentation.security.servlet6;

import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.api.agent.Trace;
import com.newrelic.api.agent.security.schema.AgentMetaData;
import com.nr.instrumentation.security.HttpServletServer;
import org.junit.Assert;
import org.junit.ClassRule;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URISyntaxException;
import java.net.URL;

@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = { "jakarta.servlet" })
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class HttpServletTest {
    @ClassRule
    public static HttpServletServer server = new HttpServletServer();

    @Test
    public void testPost() throws Exception {
        service("POST");

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        AgentMetaData metaData = introspector.getSecurityMetaData().getMetaData();
        Assert.assertTrue(metaData.isUserLevelServiceMethodEncountered());
        Assert.assertNotNull(metaData.getServiceTrace());
    }
    @Test
    public void testDelete() throws Exception {
        service("DELETE");

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        AgentMetaData metaData = introspector.getSecurityMetaData().getMetaData();
        Assert.assertTrue(metaData.isUserLevelServiceMethodEncountered());
        Assert.assertNotNull(metaData.getServiceTrace());
    }
    @Test
    public void testPUT() throws Exception {
        service("PUT");

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        AgentMetaData metaData = introspector.getSecurityMetaData().getMetaData();
        Assert.assertTrue(metaData.isUserLevelServiceMethodEncountered());
        Assert.assertNotNull(metaData.getServiceTrace());
    }

    @Test
    public void testHEAD() throws Exception {
        service("HEAD");

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        AgentMetaData metaData = introspector.getSecurityMetaData().getMetaData();
        Assert.assertTrue(metaData.isUserLevelServiceMethodEncountered());
        Assert.assertNotNull(metaData.getServiceTrace());
    }
    @Test
    public void testGET() throws Exception {
        service("GET");

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        AgentMetaData metaData = introspector.getSecurityMetaData().getMetaData();
        Assert.assertTrue(metaData.isUserLevelServiceMethodEncountered());
        Assert.assertNotNull(metaData.getServiceTrace());
    }

    @Trace(dispatcher = true)
    private void service(String Method) throws IOException, URISyntaxException {
        URL u = server.getEndPoint("").toURL();
        HttpURLConnection conn = (HttpURLConnection) u.openConnection();
        conn.setRequestProperty("content-type", "text/plain; charset=utf-8");
        conn.setRequestMethod(Method);
        conn.connect();
        conn.getResponseCode();
    }
}
