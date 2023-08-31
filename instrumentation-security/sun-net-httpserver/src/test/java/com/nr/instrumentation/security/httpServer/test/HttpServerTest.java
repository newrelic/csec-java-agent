package com.nr.instrumentation.security.httpServer.test;

import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.security.schema.operation.RXSSOperation;
import org.junit.Assert;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.List;

@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = { "com.sun.net.httpserver"})
public class HttpServerTest {
    @ClassRule
    public static Httpserver server = new Httpserver();


    @Test
    public void testHandle() throws URISyntaxException, IOException, InterruptedException {
        handle();
        Thread.sleep(100);
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        Assert.assertEquals("Extra operations detected", 1, operations.size());

        RXSSOperation targetOperation = (RXSSOperation) operations.get(0);
        Assert.assertNotNull("No target operation detected", targetOperation);
        Assert.assertEquals("Wrong case-type detected", VulnerabilityCaseType.REFLECTED_XSS, targetOperation.getCaseType());
        Assert.assertEquals("Wrong client IP detected", "127.0.0.1", targetOperation.getRequest().getClientIP());
        Assert.assertEquals("Wrong Protocol detected", "http", targetOperation.getRequest().getProtocol());

        Assert.assertEquals("Wrong port detected", server.getEndPoint().getPort(), targetOperation.getRequest().getServerPort());
        Assert.assertEquals("Wrong method name detected", "handle", targetOperation.getMethodName());
        Assert.assertEquals("Wrong Content-type detected", "text/plain", targetOperation.getRequest().getContentType());
    }

    private void handle() throws URISyntaxException, IOException {
        URL url = server.getEndPoint().toURL();
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestProperty("content-type", "text/plain; charset=utf-8");
        conn.connect();
        conn.getResponseCode();
    }
}
