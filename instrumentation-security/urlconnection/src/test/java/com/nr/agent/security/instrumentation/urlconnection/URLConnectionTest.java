package com.nr.agent.security.instrumentation.urlconnection;

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
import com.newrelic.security.test.marker.*;
import org.junit.*;
import org.junit.experimental.categories.Category;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;

import java.io.IOException;
import java.io.OutputStream;
import java.net.*;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = {"com.newrelic.agent.security.instrumentation.urlconnection"})
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@Category({ Java11IncompatibleTest.class, Java17IncompatibleTest.class, Java21IncompatibleTest.class, Java23IncompatibleTest.class })
public class URLConnectionTest {

    public String endpoint;

    @Rule
    public HttpServerRule server  = new HttpServerRule();

    @Before
    public void initServer() throws URISyntaxException, MalformedURLException, InterruptedException {
        endpoint = server.getEndPoint().toURL().toString();
    }

    @Test
    @Ignore
    public void testConnect() throws IOException {
        String headerValue = String.valueOf(UUID.randomUUID());

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        setCSECHeaders(headerValue, introspector);
        callConnect(endpoint);

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        SSRFOperation operation = (SSRFOperation) operations.get(0);
        Map<String, String> headers = server.getHeaders();
        Assert.assertEquals("Invalid executed parameters.", operation.getArg(), endpoint);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.HTTP_REQUEST, operation.getCaseType());
        Assert.assertEquals("Invalid executed class name.", "sun.net.www.protocol.http.HttpURLConnection", operation.getClassName());
        Assert.assertEquals("Invalid executed method name.", "connect", operation.getMethodName());
        verifyHeaders(headerValue, headers);

    }

    @Test
    @Ignore
    public void testConnect1() throws IOException {
        String headerValue = String.valueOf(UUID.randomUUID());

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        setCSECHeaders(headerValue, introspector);
        callConnect1(endpoint);

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        SSRFOperation operation = (SSRFOperation) operations.get(0);
        Map<String, String> headers = server.getHeaders();
        Assert.assertEquals("Invalid executed parameters.", operation.getArg(), endpoint);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.HTTP_REQUEST, operation.getCaseType());
        Assert.assertEquals("Invalid executed class name.", sun.net.www.protocol.http.HttpURLConnection.class.getName(), operation.getClassName());
        Assert.assertEquals("Invalid executed method name.", "connect", operation.getMethodName());
        verifyHeaders(headerValue, headers);
    }

    @Test
    public void testGetInputStream() throws IOException {
        String headerValue = String.valueOf(UUID.randomUUID());

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        setCSECHeaders(headerValue, introspector);
        callGetInputStream(endpoint);

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        SSRFOperation operation = (SSRFOperation) operations.get(0);
        Map<String, String> headers = server.getHeaders();
        Assert.assertEquals("Invalid executed parameters.", operation.getArg(), endpoint);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.HTTP_REQUEST, operation.getCaseType());
        Assert.assertEquals("Invalid executed class name.", "sun.net.www.protocol.http.HttpURLConnection", operation.getClassName());
        Assert.assertEquals("Invalid executed method name.", "getInputStream", operation.getMethodName());
        verifyHeaders(headerValue, headers);
    }

    @Test
    public void testGetInputStreamByGetContent() throws IOException {
        String headerValue = String.valueOf(UUID.randomUUID());

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        setCSECHeaders(headerValue, introspector);
        callGetInputStreamByGetContent(endpoint);

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        SSRFOperation operation = (SSRFOperation) operations.get(0);
        Map<String, String> headers = server.getHeaders();
        Assert.assertEquals("Invalid executed parameters.", operation.getArg(), endpoint);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.HTTP_REQUEST, operation.getCaseType());
        Assert.assertEquals("Invalid executed class name.", sun.net.www.protocol.http.HttpURLConnection.class.getName(), operation.getClassName());
        Assert.assertEquals("Invalid executed method name.", "getInputStream", operation.getMethodName());
        verifyHeaders(headerValue, headers);
    }

    @Test
    public void testGetInputStreamByGetContent1() throws IOException {
        String headerValue = String.valueOf(UUID.randomUUID());

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        setCSECHeaders(headerValue, introspector);
        callGetInputStreamByGetContent1(endpoint);

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        SSRFOperation operation = (SSRFOperation) operations.get(0);
        Map<String, String> headers = server.getHeaders();
        Assert.assertEquals("Invalid executed parameters.", operation.getArg(), endpoint);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.HTTP_REQUEST, operation.getCaseType());
        Assert.assertEquals("Invalid executed class name.", sun.net.www.protocol.http.HttpURLConnection.class.getName(), operation.getClassName());
        Assert.assertEquals("Invalid executed method name.", "getInputStream", operation.getMethodName());
        verifyHeaders(headerValue, headers);
    }

    @Test
    public void testGetInputStreamByOpenStream() throws IOException {
        String headerValue = String.valueOf(UUID.randomUUID());

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        setCSECHeaders(headerValue, introspector);
        callGetInputStreamByOpenStream(endpoint);

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        SSRFOperation operation = (SSRFOperation) operations.get(0);
        Map<String, String> headers = server.getHeaders();
        Assert.assertEquals("Invalid executed parameters.", operation.getArg(), endpoint);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.HTTP_REQUEST, operation.getCaseType());
        Assert.assertEquals("Invalid executed class name.", sun.net.www.protocol.http.HttpURLConnection.class.getName(), operation.getClassName());
        Assert.assertEquals("Invalid executed method name.", "getInputStream", operation.getMethodName());
        verifyHeaders(headerValue, headers);
    }

    @Test
    public void testGetInputStreamByConGetContent() throws IOException {
        String headerValue = String.valueOf(UUID.randomUUID());

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        setCSECHeaders(headerValue, introspector);
        callGetInputStreamByConGetContent(endpoint);

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        SSRFOperation operation = (SSRFOperation) operations.get(0);
        Map<String, String> headers = server.getHeaders();
        Assert.assertEquals("Invalid executed parameters.", operation.getArg(), endpoint);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.HTTP_REQUEST, operation.getCaseType());
        Assert.assertEquals("Invalid executed class name.", sun.net.www.protocol.http.HttpURLConnection.class.getName(), operation.getClassName());
        Assert.assertEquals("Invalid executed method name.", "getInputStream", operation.getMethodName());
        verifyHeaders(headerValue, headers);
    }

    @Test
    public void testGetInputStreamByConGetContent1() throws IOException {
        String headerValue = String.valueOf(UUID.randomUUID());

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        setCSECHeaders(headerValue, introspector);
        callGetInputStreamByConGetContent1(endpoint);

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        SSRFOperation operation = (SSRFOperation) operations.get(0);
        Map<String, String> headers = server.getHeaders();

        Assert.assertEquals("Invalid executed parameters.", operation.getArg(), endpoint);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.HTTP_REQUEST, operation.getCaseType());
        Assert.assertEquals("Invalid executed class name.", sun.net.www.protocol.http.HttpURLConnection.class.getName(), operation.getClassName());
        Assert.assertEquals("Invalid executed method name.", "getInputStream", operation.getMethodName());
        verifyHeaders(headerValue, headers);
    }

    @Test
    @Ignore
    public void testGetOutputStream() throws IOException {
        String headerValue = String.valueOf(UUID.randomUUID());

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        setCSECHeaders(headerValue, introspector);
        callGetOutputStream(endpoint);

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        SSRFOperation operation = (SSRFOperation) operations.get(0);
        Map<String, String> headers = server.getHeaders();

        Assert.assertEquals("Invalid executed parameters.", operation.getArg(), endpoint);
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.HTTP_REQUEST, operation.getCaseType());
        Assert.assertEquals("Invalid executed class name.", "sun.net.www.protocol.http.HttpURLConnection", operation.getClassName());
        Assert.assertEquals("Invalid executed method name.", "getOutputStream", operation.getMethodName());
        verifyHeaders(headerValue, headers);
    }

    @Trace(dispatcher = true)
    private void callConnect(String endpoint) throws IOException {
        URL u = new URL(endpoint);
        HttpURLConnection conn = (HttpURLConnection) u.openConnection();
        conn.connect();
    }

    @Trace(dispatcher = true)
    private void callConnect1(String endpoint) throws IOException {
        new URL(endpoint).openConnection().connect();
    }

    @Trace(dispatcher = true)
    private void callGetInputStreamByConGetContent(String endpoint) throws IOException {
        new URL(endpoint).openConnection().getContent();
    }

    @Trace(dispatcher = true)
    private void callGetInputStreamByConGetContent1(String endpoint) throws IOException {
        new URL(endpoint).openConnection().getContent(new Class[]{String.class});
    }

    @Trace(dispatcher = true)
    private void callGetInputStream(String endpoint) throws IOException {
        new URL(endpoint).openConnection().getInputStream();
    }

    @Trace(dispatcher = true)
    private void callGetInputStreamByGetContent(String endpoint) throws IOException {
        new URL(endpoint).getContent();
    }

    @Trace(dispatcher = true)
    private void callGetInputStreamByGetContent1(String endpoint) throws IOException {
        new URL(endpoint).getContent(new Class[]{String.class});
    }

    @Trace(dispatcher = true)
    private void callGetInputStreamByOpenStream(String endpoint) throws IOException {
        new URL(endpoint).openStream();
    }

    @Trace(dispatcher = true)
    private void callGetOutputStream(String endpoint) throws IOException {
        URL u = new URL(endpoint);
        URLConnection conn = u.openConnection();
        conn.setDoOutput(true);

        try (OutputStream output = conn.getOutputStream()) {
            output.write(1);
        }
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
}
