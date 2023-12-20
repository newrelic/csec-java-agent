package com.nr.agent.security.instrumentation.httpclient40;

import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.agent.security.introspec.internal.HttpServerRule;
import com.newrelic.api.agent.Trace;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.instrumentation.helpers.ServletHelper;
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
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.IOException;
import java.net.URISyntaxException;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = "com.newrelic.agent.security.instrumentation.httpclient40")
public class HttpClientTest {
    @ClassRule
    public static HttpServerRule server = new HttpServerRule();

    @Test
    public void testExecute() throws URISyntaxException, IOException {
        String headerValue = String.valueOf(UUID.randomUUID());

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        setCSECHeaders(headerValue, introspector);

        callExecute();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        SSRFOperation operation = (SSRFOperation) operations.get(0);
        Map<String, String> headers = server.getHeaders();
        Assert.assertEquals("Invalid executed parameters.", server.getEndPoint().toString(), operation.getArg());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.HTTP_REQUEST, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        verifyHeaders(headerValue, headers);
    }

    @Test
    public void testExecute1() throws URISyntaxException, IOException {

        String headerValue = String.valueOf(UUID.randomUUID());

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        setCSECHeaders(headerValue, introspector);
        callExecute1();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        SSRFOperation operation = (SSRFOperation) operations.get(0);
        Map<String, String> headers = server.getHeaders();
        Assert.assertEquals("Invalid executed parameters.", server.getEndPoint().toString(), operation.getArg());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.HTTP_REQUEST, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        verifyHeaders(headerValue, headers);
    }

    @Test
    public void testExecute2() throws URISyntaxException, IOException {

        String headerValue = String.valueOf(UUID.randomUUID());

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        setCSECHeaders(headerValue, introspector);
        callExecute2();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        SSRFOperation operation = (SSRFOperation) operations.get(0);
        Map<String, String> headers = server.getHeaders();
        Assert.assertEquals("Invalid executed parameters.", server.getEndPoint().toString(), operation.getArg());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.HTTP_REQUEST, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        verifyHeaders(headerValue, headers);

    }

    @Test
    public void testExecute3() throws URISyntaxException, IOException {

        String headerValue = String.valueOf(UUID.randomUUID());

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        setCSECHeaders(headerValue, introspector);
        callExecute3();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        SSRFOperation operation = (SSRFOperation) operations.get(0);
        Map<String, String> headers = server.getHeaders();
        Assert.assertEquals("Invalid executed parameters.", server.getEndPoint().toString(), operation.getArg());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.HTTP_REQUEST, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        verifyHeaders(headerValue, headers);

    }

    @Test
    public void testExecute4() throws Exception {


        String headerValue = String.valueOf(UUID.randomUUID());

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        setCSECHeaders(headerValue, introspector);
        callExecute4();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        SSRFOperation operation = (SSRFOperation) operations.get(0);
        Map<String, String> headers = server.getHeaders();
        Assert.assertEquals("Invalid executed parameters.", server.getEndPoint().toString(), operation.getArg());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.HTTP_REQUEST, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        verifyHeaders(headerValue, headers);

    }

    @Test
    public void testExecute5() throws Exception {


        String headerValue = String.valueOf(UUID.randomUUID());

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        setCSECHeaders(headerValue, introspector);
        callExecute5();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        SSRFOperation operation = (SSRFOperation) operations.get(0);
        Map<String, String> headers = server.getHeaders();
        Assert.assertEquals("Invalid executed parameters.", server.getEndPoint().toString(), operation.getArg());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.HTTP_REQUEST, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        verifyHeaders(headerValue, headers);

    }

    @Test
    public void testExecute6() throws Exception {


        String headerValue = String.valueOf(UUID.randomUUID());

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        setCSECHeaders(headerValue, introspector);
        callExecute6();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        SSRFOperation operation = (SSRFOperation) operations.get(0);
        Map<String, String> headers = server.getHeaders();
        Assert.assertEquals("Invalid executed parameters.", server.getEndPoint().toString(), operation.getArg());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.HTTP_REQUEST, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        verifyHeaders(headerValue, headers);

    }

    @Test
    public void testExecute7() throws Exception {


        String headerValue = String.valueOf(UUID.randomUUID());

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        setCSECHeaders(headerValue, introspector);
        callExecute7();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        SSRFOperation operation = (SSRFOperation) operations.get(0);
        Map<String, String> headers = server.getHeaders();
        Assert.assertEquals("Invalid executed parameters.", server.getEndPoint().toString(), operation.getArg());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.HTTP_REQUEST, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        verifyHeaders(headerValue, headers);

    }

    private void setCSECHeaders(String headerValue, SecurityIntrospector introspector) {
        introspector.setK2FuzzRequestId(headerValue+"a");
        introspector.setK2ParentId(headerValue+"b");
        introspector.setK2TracingData(headerValue);
    }

    private void verifyHeaders(String headerValue, Map<String, String> headers) {
        Assert.assertTrue(String.format("Missing K2 header: %s", ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID), headers.containsKey(ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID));
        Assert.assertEquals(String.format("Invalid K2 header value for:  %s", ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID), headerValue+"a", headers.get(ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID));
        Assert.assertTrue(String.format("Missing K2 header: %s", GenericHelper.CSEC_PARENT_ID), headers.containsKey(GenericHelper.CSEC_PARENT_ID));
        Assert.assertEquals(String.format("Invalid K2 header value for:  %s", GenericHelper.CSEC_PARENT_ID), headerValue+"b", headers.get(GenericHelper.CSEC_PARENT_ID));
        Assert.assertTrue(String.format("Missing K2 header: %s", ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER), headers.containsKey(ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER.toLowerCase()));
        Assert.assertEquals(String.format("Invalid K2 header value for:  %s", ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER), String.format("%s;DUMMY_UUID/dummy-api-id/dummy-exec-id;",
                headerValue), headers.get(
                ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER.toLowerCase()));
    }

    @Trace(dispatcher = true)
    public void callExecute() throws URISyntaxException, IOException {
        try (CloseableHttpClient httpclient = HttpClients.createDefault()) {
            HttpGet httpGet = new HttpGet(server.getEndPoint().toString());
            httpclient.execute(httpGet);
        }
    }

    @Trace(dispatcher = true)
    public void callExecute1() throws URISyntaxException, IOException {
        try (CloseableHttpClient httpclient = HttpClients.createDefault()) {
            HttpGet httpGet = new HttpGet(server.getEndPoint().toString());
            HttpContext httpContext = new BasicHttpContext();
            httpclient.execute(httpGet, httpContext);
        }
    }

    @Trace(dispatcher = true)
    public void callExecute2() throws URISyntaxException, IOException {
        try (CloseableHttpClient httpclient = HttpClients.createDefault()) {
            HttpHost httpHost = new HttpHost(server.getEndPoint().getHost(), server.getEndPoint().getPort(), server.getEndPoint().getScheme());
            HttpGet httpGet = new HttpGet(server.getEndPoint().toString());
            httpclient.execute(httpHost, httpGet);
        }
    }

    @Trace(dispatcher = true)
    public void callExecute3() throws URISyntaxException, IOException {
        try(CloseableHttpClient httpclient = HttpClients.createDefault()) {
            HttpHost httpHost = new HttpHost(server.getEndPoint().getHost(), server.getEndPoint().getPort(), server.getEndPoint().getScheme());
            HttpGet httpGet = new HttpGet(server.getEndPoint().toString());
            HttpContext httpContext = new BasicHttpContext();
            httpclient.execute(httpHost, httpGet, httpContext);
        }
    }

    @Trace(dispatcher = true)
    public void callExecute4() throws Exception {
        try (CloseableHttpClient httpclient = HttpClients.createDefault()) {
            HttpGet httpGet = new HttpGet(server.getEndPoint().toString());
            ResponseHandler<String> responseHandler = new BasicResponseHandler();
            httpclient.execute(httpGet, responseHandler);
        }
    }

    @Trace(dispatcher = true)
    public void callExecute5() throws Exception {
        try(CloseableHttpClient httpclient = HttpClients.createDefault()) {
            HttpGet httpGet = new HttpGet(server.getEndPoint().toString());
            ResponseHandler<String> responseHandler = new BasicResponseHandler();
            HttpContext httpContext = new BasicHttpContext();
            httpclient.execute(httpGet, responseHandler, httpContext);
        }
    }

    @Trace(dispatcher = true)
    public void callExecute6() throws Exception {
        try(CloseableHttpClient httpclient = HttpClients.createDefault()) {
            HttpGet httpGet = new HttpGet(server.getEndPoint().toString());
            ResponseHandler<String> responseHandler = new BasicResponseHandler();
            HttpHost httpHost = new HttpHost(server.getEndPoint().getHost(), server.getEndPoint().getPort(), server.getEndPoint().getScheme());
            httpclient.execute(httpHost, httpGet, responseHandler);
        }
    }

    @Trace(dispatcher = true)
    public void callExecute7() throws Exception {
        try(CloseableHttpClient httpclient = HttpClients.createDefault()) {
            HttpGet httpGet = new HttpGet(server.getEndPoint().toString());
            ResponseHandler<String> responseHandler = new BasicResponseHandler();
            HttpHost httpHost = new HttpHost(server.getEndPoint().getHost(), server.getEndPoint().getPort(), server.getEndPoint().getScheme());
            HttpContext httpContext = new BasicHttpContext();
            httpclient.execute(httpHost, httpGet, responseHandler, httpContext);
        }
    }
}
