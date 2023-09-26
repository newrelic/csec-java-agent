package com.nr.instrumentation.security.httpclientJDK11;

import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.agent.security.introspec.internal.HttpServerRule;
import com.newrelic.api.agent.Trace;
import com.newrelic.api.agent.security.instrumentation.helpers.ServletHelper;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.security.schema.operation.SSRFOperation;
import com.newrelic.security.test.marker.Java8IncompatibleTest;
import org.junit.Assert;
import org.junit.ClassRule;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;

import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

@Category({ Java8IncompatibleTest.class })
@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = { "nr.java.net.http", "nr.jdk.internal.net.http", "nr.security.java.net.http.helper" })
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class HttpClientTest {

    @ClassRule
    public static HttpServerRule server = new HttpServerRule();

    @Test
    public void testSendAsync() throws Exception {
        String headerValue = String.valueOf(UUID.randomUUID());

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        introspector.setK2FuzzRequestId(headerValue);
        introspector.setK2TracingData(headerValue);

        send();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        SSRFOperation operation = (SSRFOperation) operations.get(0);
        Map<String, String> headers = server.getHeaders();

        Assert.assertEquals("Invalid executed parameters.", server.getEndPoint().toString(), operation.getArg());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.HTTP_REQUEST, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "sendAsync", operation.getMethodName());
        Assert.assertTrue(String.format("Missing CSEC header: %s", ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID), headers.containsKey(ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID));
        Assert.assertEquals(String.format("Invalid CSEC header value for:  %s", ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID), headerValue, headers.get(ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID));
        Assert.assertTrue(String.format("Missing CSEC header: %s", ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER), headers.containsKey(ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER.toLowerCase()));
        Assert.assertEquals(
                String.format("Invalid CSEC header value for:  %s",
                        ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER), String.format("%s;DUMMY_UUID/dummy-api-id/dummy-exec-id;",headerValue),
                headers.get(ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER.toLowerCase())
        );
    }

    @Test
    public void testSendAsync1() throws Exception {
        String headerValue = String.valueOf(UUID.randomUUID());

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        introspector.setK2FuzzRequestId(headerValue);
        introspector.setK2TracingData(headerValue);

        sendAsync();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        SSRFOperation operation = (SSRFOperation) operations.get(0);
        Map<String, String> headers = server.getHeaders();

        Assert.assertEquals("Invalid executed parameters.", server.getEndPoint().toString(), operation.getArg());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.HTTP_REQUEST, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "sendAsync", operation.getMethodName());
        Assert.assertTrue(String.format("Missing CSEC header: %s", ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID), headers.containsKey(ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID));
        Assert.assertEquals(String.format("Invalid CSEC header value for:  %s", ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID), headerValue, headers.get(ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID));
        Assert.assertTrue(String.format("Missing CSEC header: %s", ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER), headers.containsKey(ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER.toLowerCase()));
        Assert.assertEquals(
                String.format("Invalid CSEC header value for:  %s",
                        ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER), String.format("%s;DUMMY_UUID/dummy-api-id/dummy-exec-id;",headerValue),
                headers.get(ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER.toLowerCase())
        );
    }

    @Test
    public void testSendAsync2() throws Exception {
        String headerValue = String.valueOf(UUID.randomUUID());

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        introspector.setK2FuzzRequestId(headerValue);
        introspector.setK2TracingData(headerValue);

        sendAsync1();

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        SSRFOperation operation = (SSRFOperation) operations.get(0);
        Map<String, String> headers = server.getHeaders();

        Assert.assertEquals("Invalid executed parameters.", server.getEndPoint().toString(), operation.getArg());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.HTTP_REQUEST, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "sendAsync", operation.getMethodName());
        Assert.assertTrue(String.format("Missing CSEC header: %s", ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID), headers.containsKey(ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID));
        Assert.assertEquals(String.format("Invalid CSEC header value for:  %s", ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID), headerValue, headers.get(ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID));
        Assert.assertTrue(String.format("Missing CSEC header: %s", ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER), headers.containsKey(ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER.toLowerCase()));
        Assert.assertEquals(
                String.format("Invalid CSEC header value for:  %s",
                        ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER), String.format("%s;DUMMY_UUID/dummy-api-id/dummy-exec-id;",headerValue),
                headers.get(ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER.toLowerCase())
        );
    }

    @Trace(dispatcher = true)
    private void send() throws Exception {
        HttpRequest httpRequest = HttpRequest.newBuilder()
                .uri(server.getEndPoint())
                .GET()
                .build();

        HttpClient httpClient = HttpClient.newHttpClient();
        httpClient.send(httpRequest, HttpResponse.BodyHandlers.ofString());
    }
    @Trace(dispatcher = true)
    private void sendAsync() throws Exception {
        HttpRequest httpRequest = HttpRequest.newBuilder()
                .uri(server.getEndPoint())
                .GET()
                .build();

        HttpClient httpClient = HttpClient.newHttpClient();
        CompletableFuture<HttpResponse<String>> response2 = httpClient.sendAsync(httpRequest, HttpResponse.BodyHandlers.ofString());
        response2.get();
    }

    @Trace(dispatcher = true)
    private void sendAsync1() throws Exception {
        HttpRequest httpRequest = HttpRequest.newBuilder()
                .uri(server.getEndPoint())
                .GET()
                .build();

        HttpClient httpClient = HttpClient.newHttpClient();
        CompletableFuture<HttpResponse<String>> response2 = httpClient.sendAsync(httpRequest, HttpResponse.BodyHandlers.ofString(), null);
        response2.get();
    }
}
