package com.nr.instrumentation.security.urlconnection;

import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.agent.security.introspec.internal.HttpServerRule;
import com.newrelic.api.agent.Trace;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.security.schema.operation.SSRFOperation;
import org.junit.Assert;
import org.junit.Before;
import org.junit.FixMethodOrder;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLConnection;
import java.util.List;

@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = {"com.nr.agent.instrumentation.security.urlconnection"})
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class URLConnectionTest {

    public String endpoint;
    @Rule
    public HttpServerRule server  = new HttpServerRule();

    @Before
    public void initServer() throws URISyntaxException, MalformedURLException {
        endpoint = server.getEndPoint().toURL().toString();
    }

    @Test
    public void testConnect() throws IOException {
        callConnect(endpoint);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        SSRFOperation operation = (SSRFOperation) operations.get(0);
        Assert.assertEquals("Invalid executed parameters.", operation.getArg(), endpoint);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.HTTP_REQUEST, operation.getCaseType());
        Assert.assertEquals("Invalid executed class name.", sun.net.www.protocol.http.HttpURLConnection.class.getName(), operation.getClassName());
        Assert.assertEquals("Invalid executed method name.", "connect", operation.getMethodName());
    }

    @Test
    public void testGetInputStream() throws IOException {
        callGetInputStream(endpoint);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        SSRFOperation operation = (SSRFOperation) operations.get(0);
        Assert.assertEquals("Invalid executed parameters.", operation.getArg(), endpoint);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.HTTP_REQUEST, operation.getCaseType());
        Assert.assertEquals("Invalid executed class name.", sun.net.www.protocol.http.HttpURLConnection.class.getName(), operation.getClassName());
        Assert.assertEquals("Invalid executed method name.", "getInputStream", operation.getMethodName());
    }

    @Test
    public void testGetOutputStream() throws IOException {
        callGetOutputStream(endpoint);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        SSRFOperation operation = (SSRFOperation) operations.get(0);
        Assert.assertEquals("Invalid executed parameters.", operation.getArg(), endpoint);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.HTTP_REQUEST, operation.getCaseType());
        Assert.assertEquals("Invalid executed class name.", sun.net.www.protocol.http.HttpURLConnection.class.getName(), operation.getClassName());
        Assert.assertEquals("Invalid executed method name.", "getOutputStream", operation.getMethodName());
    }

    @Trace(dispatcher = true)
    public void callConnect(String endpoint) throws IOException {
        URL u = new URL(endpoint);
        HttpURLConnection conn = (HttpURLConnection) u.openConnection();
        conn.connect();
    }

    @Trace(dispatcher = true)
    private void callGetInputStream(String endpoint) throws IOException {
        URL u = new URL(endpoint);
        URLConnection conn = u.openConnection();
        InputStream in = conn.getInputStream();
    }

    @Trace(dispatcher = true)
    private void callGetOutputStream(String endpoint) throws IOException {
        URL u = new URL(endpoint);
        URLConnection conn = u.openConnection();
        conn.setDoOutput(true);

        try (OutputStream output = conn.getOutputStream()) {
            System.out.println(output);
        }
    }
}
