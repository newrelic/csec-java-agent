package com.nr.instrumentation.security.httpclient4;

import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.agent.security.introspec.internal.HttpServerRule;
import com.newrelic.api.agent.Trace;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.security.schema.operation.SSRFOperation;
import org.apache.http.HttpHost;
import org.apache.http.client.ResponseHandler;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.BasicResponseHandler;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.protocol.BasicHttpContext;
import org.apache.http.protocol.HttpContext;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.IOException;
import java.net.URISyntaxException;
import java.util.List;

@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = "org.apache.http.client")
public class HttpClientTest {
    @Rule
    public HttpServerRule server = new HttpServerRule();

    @Test
    public void testExecute() throws URISyntaxException, IOException {
        callExecute();
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        SSRFOperation operation = (SSRFOperation) operations.get(0);
        Assert.assertEquals("Invalid executed parameters.", server.getEndPoint().toString(), operation.getArg());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.HTTP_REQUEST, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());

    }

    @Test
    public void testExecute1() throws URISyntaxException, IOException {
        callExecute1();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        SSRFOperation operation = (SSRFOperation) operations.get(0);
        Assert.assertEquals("Invalid executed parameters.", server.getEndPoint().toString(), operation.getArg());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.HTTP_REQUEST, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
    }

    @Test
    public void testExecute2() throws URISyntaxException, IOException {
        callExecute2();
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        SSRFOperation operation = (SSRFOperation) operations.get(0);
        Assert.assertEquals("Invalid executed parameters.", server.getEndPoint().toString(), operation.getArg());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.HTTP_REQUEST, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());

    }

    @Test
    public void testExecute3() throws URISyntaxException, IOException {
        callExecute3();
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        SSRFOperation operation = (SSRFOperation) operations.get(0);
        Assert.assertEquals("Invalid executed parameters.", server.getEndPoint().toString(), operation.getArg());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.HTTP_REQUEST, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());

    }

    @Test
    public void testExecute4() throws Exception {
        callExecute4();
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        SSRFOperation operation = (SSRFOperation) operations.get(0);
        Assert.assertEquals("Invalid executed parameters.", server.getEndPoint().toString(), operation.getArg());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.HTTP_REQUEST, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());

    }

    @Test
    public void testExecute5() throws Exception {
        callExecute5();
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        SSRFOperation operation = (SSRFOperation) operations.get(0);
        Assert.assertEquals("Invalid executed parameters.", server.getEndPoint().toString(), operation.getArg());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.HTTP_REQUEST, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());

    }

    @Test
    public void testExecute6() throws Exception {
        callExecute6();
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        SSRFOperation operation = (SSRFOperation) operations.get(0);
        Assert.assertEquals("Invalid executed parameters.", server.getEndPoint().toString(), operation.getArg());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.HTTP_REQUEST, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());

    }

    @Test
    public void testExecute7() throws Exception {
        callExecute7();
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        SSRFOperation operation = (SSRFOperation) operations.get(0);
        Assert.assertEquals("Invalid executed parameters.", server.getEndPoint().toString(), operation.getArg());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.HTTP_REQUEST, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());

    }

    @Trace(dispatcher = true)
    public void callExecute() throws URISyntaxException, IOException {
        CloseableHttpClient httpclient = HttpClients.createDefault();
        HttpGet httpGet = new HttpGet(server.getEndPoint().toString());
        httpclient.execute(httpGet);
    }

    @Trace(dispatcher = true)
    public void callExecute1() throws URISyntaxException, IOException {
        CloseableHttpClient httpclient = HttpClients.createDefault();
        HttpGet httpGet = new HttpGet(server.getEndPoint().toString());
        HttpContext httpContext = new BasicHttpContext();
        httpclient.execute(httpGet, httpContext);
    }

    @Trace(dispatcher = true)
    public void callExecute2() throws URISyntaxException, IOException {
        CloseableHttpClient httpclient = HttpClients.createDefault();
        HttpHost httpHost = new HttpHost(server.getEndPoint().getHost(), server.getEndPoint().getPort(), server.getEndPoint().getScheme());
        HttpGet httpGet = new HttpGet(server.getEndPoint().toString());
        httpclient.execute(httpHost, httpGet);
    }

    @Trace(dispatcher = true)
    public void callExecute3() throws URISyntaxException, IOException {
        CloseableHttpClient httpclient = HttpClients.createDefault();
        HttpHost httpHost = new HttpHost(server.getEndPoint().getHost(), server.getEndPoint().getPort(), server.getEndPoint().getScheme());
        HttpGet httpGet = new HttpGet(server.getEndPoint().toString());
        HttpContext httpContext = new BasicHttpContext();
        httpclient.execute(httpHost, httpGet, httpContext);
    }

    @Trace(dispatcher = true)
    public void callExecute4() throws Exception {
        CloseableHttpClient httpclient = HttpClients.createDefault();
        HttpGet httpGet = new HttpGet(server.getEndPoint().toString());
        ResponseHandler<String> responseHandler = new BasicResponseHandler();
        httpclient.execute(httpGet, responseHandler);
    }

    @Trace(dispatcher = true)
    public void callExecute5() throws Exception {
        CloseableHttpClient httpclient = HttpClients.createDefault();
        HttpGet httpGet = new HttpGet(server.getEndPoint().toString());
        ResponseHandler<String> responseHandler = new BasicResponseHandler();
        HttpContext httpContext = new BasicHttpContext();
        httpclient.execute(httpGet, responseHandler, httpContext);
    }

    @Trace(dispatcher = true)
    public void callExecute6() throws Exception {
        CloseableHttpClient httpclient = HttpClients.createDefault();
        HttpGet httpGet = new HttpGet(server.getEndPoint().toString());
        ResponseHandler<String> responseHandler = new BasicResponseHandler();
        HttpHost httpHost = new HttpHost(server.getEndPoint().getHost(), server.getEndPoint().getPort(), server.getEndPoint().getScheme());
        httpclient.execute(httpHost, httpGet, responseHandler);
    }

    @Trace(dispatcher = true)
    public void callExecute7() throws Exception {
        CloseableHttpClient httpclient = HttpClients.createDefault();
        HttpGet httpGet = new HttpGet(server.getEndPoint().toString());
        ResponseHandler<String> responseHandler = new BasicResponseHandler();
        HttpHost httpHost = new HttpHost(server.getEndPoint().getHost(), server.getEndPoint().getPort(), server.getEndPoint().getScheme());
        HttpContext httpContext = new BasicHttpContext();
        httpclient.execute(httpHost, httpGet, responseHandler, httpContext);
    }

}
