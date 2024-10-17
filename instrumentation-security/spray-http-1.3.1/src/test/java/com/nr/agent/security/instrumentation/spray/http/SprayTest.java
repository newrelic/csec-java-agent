package com.nr.agent.security.instrumentation.spray.http;

import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.instrumentation.helpers.ServletHelper;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.StringUtils;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.security.schema.operation.RXSSOperation;
import org.junit.Assert;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.ServerSocket;
import java.net.URL;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = { "spray", "scala" })
public class SprayTest {

    @ClassRule
    public static HttpServer server = HttpServer$.MODULE$.apply(getRandomPort());
    private static int port;

    @Test
    public void testGet() throws IOException {
        makeRequest("GET", StringUtils.EMPTY);
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertNotNull(operations);
        Assert.assertEquals(1, operations.size());

        RXSSOperation operation = (RXSSOperation) operations.get(0);
        Assert.assertNotNull("No target operation detected", operation);
        Assert.assertEquals("Wrong case-type detected", VulnerabilityCaseType.REFLECTED_XSS, operation.getCaseType());
        Assert.assertEquals("Wrong method name detected", "marshalTo", operation.getMethodName());

        Assert.assertNotNull("Empty request detected", operation.getRequest());
        Assert.assertEquals("Wrong Protocol detected", "http", operation.getRequest().getProtocol());
        Assert.assertEquals("Wrong port detected", port, operation.getRequest().getServerPort());
        Assert.assertEquals("Wrong Content-type detected", StringUtils.EMPTY, operation.getRequest().getContentType());

        Assert.assertNotNull("Empty response detected", operation.getResponse());
        Assert.assertEquals("Wrong port detected", "testing API", operation.getResponse().getBody().toString());
        Assert.assertEquals("Wrong Content-type detected", "text/plain", operation.getResponse().getResponseContentType());

    }
    @Test
    public void testPost() throws IOException {
        makeRequest("POST", StringUtils.EMPTY);
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertNotNull(operations);
        Assert.assertEquals(1, operations.size());

        RXSSOperation operation = (RXSSOperation) operations.get(0);
        Assert.assertNotNull("No target operation detected", operation);
        Assert.assertEquals("Wrong case-type detected", VulnerabilityCaseType.REFLECTED_XSS, operation.getCaseType());
        Assert.assertEquals("Wrong method name detected", "marshalTo", operation.getMethodName());

        Assert.assertNotNull("Empty request detected", operation.getRequest());
        Assert.assertEquals("Wrong Protocol detected", "http", operation.getRequest().getProtocol());
        Assert.assertEquals("Wrong port detected", port, operation.getRequest().getServerPort());
        Assert.assertEquals("Wrong Content-type detected", "text/plain", operation.getRequest().getContentType());
        Assert.assertEquals("Wrong Content-type detected", "data", operation.getRequest().getBody().toString());

        Assert.assertNotNull("Empty response detected", operation.getResponse());
        Assert.assertEquals("Wrong port detected", "testing API", operation.getResponse().getBody().toString());
        Assert.assertEquals("Wrong Content-type detected", "text/plain", operation.getResponse().getResponseContentType());

    }

    @Test
    public void testWithCSECHeader() throws IOException {
        String headerValue = String.valueOf(UUID.randomUUID());
        makeRequest("GET", headerValue);
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertNotNull(operations);
        Assert.assertEquals(1, operations.size());

        RXSSOperation operation = (RXSSOperation) operations.get(0);
        Assert.assertNotNull("No target operation detected", operation);
        Assert.assertEquals("Wrong case-type detected", VulnerabilityCaseType.REFLECTED_XSS, operation.getCaseType());
        Assert.assertEquals("Wrong method name detected", "marshalTo", operation.getMethodName());

        Assert.assertNotNull("Empty request detected", operation.getRequest());
        Assert.assertEquals("Wrong Protocol detected", "http", operation.getRequest().getProtocol());
        Assert.assertEquals("Wrong port detected", port, operation.getRequest().getServerPort());
        Assert.assertEquals("Wrong Content-type detected", StringUtils.EMPTY, operation.getRequest().getContentType());

        Assert.assertNotNull("Empty response detected", operation.getResponse());
        Assert.assertEquals("Wrong port detected", "testing API", operation.getResponse().getBody().toString());
        Assert.assertEquals("Wrong Content-type detected", "text/plain", operation.getResponse().getResponseContentType());

        Map<String, String> headers = operation.getRequest().getHeaders();
        Assert.assertTrue(
                String.format("Missing header: %s", ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID),
                headers.containsKey(ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID)
        );
        Assert.assertEquals(
                String.format("Invalid header value for:  %s", ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID),
                headerValue,
                headers.get(ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID)
        );
        Assert.assertTrue(
                String.format("Missing header: %s", ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER),
                headers.containsKey(ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER.toLowerCase())
        );
        Assert.assertEquals(
                String.format("Invalid header value for:  %s", ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER),
                headerValue,
                headers.get(ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER.toLowerCase())
        );
        Assert.assertTrue(
                String.format("Missing header: %s", GenericHelper.CSEC_PARENT_ID),
                headers.containsKey(GenericHelper.CSEC_PARENT_ID.toLowerCase())
        );
        Assert.assertEquals(
                String.format("Invalid header value for:  %s", GenericHelper.CSEC_PARENT_ID),
                headerValue,
                headers.get(GenericHelper.CSEC_PARENT_ID.toLowerCase())
        );
    }

    private static int getRandomPort(){
        try (ServerSocket socket = new ServerSocket(0)){
            return port = socket.getLocalPort();
        } catch (IOException e) {
            throw new RuntimeException("Unable to allocate ephemeral port");
        }
    }

    private void makeRequest(String method, String csecHeaders) throws IOException {
        String ENDPOINT = String.format("http://localhost:%d/test", port);
        HttpURLConnection conn = (HttpURLConnection) new URL(ENDPOINT).openConnection();
        conn.setRequestMethod(method);
        conn.setDoOutput(true);
        conn.setRequestProperty("Content-Type", "text/plain");
        if (method.equalsIgnoreCase("POST")) {
            conn.getOutputStream().write("data".getBytes());
        }
        if (!csecHeaders.isEmpty()) {
            conn.setRequestProperty(ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID, csecHeaders);
            conn.setRequestProperty(ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER, csecHeaders);
            conn.setRequestProperty(GenericHelper.CSEC_PARENT_ID, csecHeaders);
        }
        conn.connect();
        System.out.println("response status: " + conn.getResponseCode());
    }
}
