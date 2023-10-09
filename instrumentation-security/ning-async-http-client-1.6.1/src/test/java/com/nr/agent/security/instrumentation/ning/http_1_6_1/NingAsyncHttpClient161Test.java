package com.nr.agent.security.instrumentation.ning.http_1_6_1;

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
import com.ning.http.client.AsyncCompletionHandler;
import com.ning.http.client.AsyncHttpClient;
import com.ning.http.client.Request;
import com.ning.http.client.RequestBuilder;
import com.ning.http.client.Response;
import org.junit.Assert;
import org.junit.ClassRule;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;

import java.io.IOException;
import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;

@RunWith(SecurityInstrumentationTestRunner.class)
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@InstrumentationTestConfig(includePrefixes = { "com.newrelic.agent.security.instrumentation.ning.http_1_6_1", "com.ning" })
public class NingAsyncHttpClient161Test {

    private static final int TIMEOUT = 30000;

    @ClassRule
    public static HttpServerRule server = new HttpServerRule();

    @Test
    public void testPrepare() throws Exception {
        URI endpoint = server.getEndPoint();
        String host = endpoint.getHost();

        String headerValue = String.valueOf(UUID.randomUUID());

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        setCSECHeaders(headerValue, introspector);

        makeAsyncRequest(endpoint.toURL().toString());

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
    public void testPrepareGet() throws Exception {
        URI endpoint = server.getEndPoint();
        String host = endpoint.getHost();

        String headerValue = String.valueOf(UUID.randomUUID());

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        setCSECHeaders(headerValue, introspector);

        makeAsyncRequestGet(endpoint.toURL().toString());

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
    public void testPreparePost() throws Exception {
        URI endpoint = server.getEndPoint();
        String host = endpoint.getHost();

        String headerValue = String.valueOf(UUID.randomUUID());

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        setCSECHeaders(headerValue, introspector);

        makeAsyncRequestPost(endpoint.toURL().toString());

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
    public void testPreparePut() throws Exception {
        URI endpoint = server.getEndPoint();
        String host = endpoint.getHost();

        String headerValue = String.valueOf(UUID.randomUUID());

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        setCSECHeaders(headerValue, introspector);

        makeAsyncRequestPut(endpoint.toURL().toString());

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
    public void testPrepareDelete() throws Exception {
        URI endpoint = server.getEndPoint();
        String host = endpoint.getHost();

        String headerValue = String.valueOf(UUID.randomUUID());

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        setCSECHeaders(headerValue, introspector);

        makeAsyncRequestDelete(endpoint.toURL().toString());

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
    public void testPrepareHead() throws Exception {
        URI endpoint = server.getEndPoint();
        String host = endpoint.getHost();

        String headerValue = String.valueOf(UUID.randomUUID());

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        setCSECHeaders(headerValue, introspector);

        makeAsyncRequestHead(endpoint.toURL().toString());

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
    public void testPrepareOptions() throws Exception {
        URI endpoint = server.getEndPoint();
        String host = endpoint.getHost();

        String headerValue = String.valueOf(UUID.randomUUID());

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        setCSECHeaders(headerValue, introspector);

        makeAsyncRequestOptions(endpoint.toURL().toString());

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
    public void testExecuteRequest1() throws Exception {
        URI endpoint = server.getEndPoint();
        String host = endpoint.getHost();

        String headerValue = String.valueOf(UUID.randomUUID());

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        setCSECHeaders(headerValue, introspector);

        makeAsyncExecuteRequest1(endpoint.toURL().toString());

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
    public void testExecuteRequest2() throws Exception {
        URI endpoint = server.getEndPoint();
        String host = endpoint.getHost();

        String headerValue = String.valueOf(UUID.randomUUID());

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        setCSECHeaders(headerValue, introspector);

        makeAsyncExecuteRequest2(endpoint.toURL().toString());

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        SSRFOperation operation = (SSRFOperation) operations.get(0);
        Map<String, String> headers = server.getHeaders();
        Assert.assertEquals("Invalid executed parameters.", server.getEndPoint().toString(), operation.getArg());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.HTTP_REQUEST, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        verifyHeaders(headerValue, headers);
    }

    @Trace(dispatcher = true)
    public static int makeAsyncRequestGet(String url) {
        AsyncHttpClient client = new AsyncHttpClient();
        try {
            AsyncHttpClient.BoundRequestBuilder builder = client.prepareGet(url);
            Future<Response> future = builder.execute();
            Response response = future.get();
            return response.getStatusCode();
        } catch (Exception e) {
            return -1;
        } finally {
            client.close();
        }
    }

    @Trace(dispatcher = true)
    public static int makeAsyncRequestPost(String url) {
        AsyncHttpClient client = new AsyncHttpClient();
        try {
            AsyncHttpClient.BoundRequestBuilder builder = client.preparePost(url);
            Future<Response> future = builder.execute();
            Response response = future.get();
            return response.getStatusCode();
        } catch (Exception e) {
            return -1;
        } finally {
            client.close();
        }
    }

    @Trace(dispatcher = true)
    public static int makeAsyncRequestPut(String url) {
        AsyncHttpClient client = new AsyncHttpClient();
        try {
            AsyncHttpClient.BoundRequestBuilder builder = client.preparePut(url);
            Future<Response> future = builder.execute();
            Response response = future.get();
            return response.getStatusCode();
        } catch (Exception e) {
            return -1;
        } finally {
            client.close();
        }
    }

    @Trace(dispatcher = true)
    public static int makeAsyncRequestDelete(String url) {
        AsyncHttpClient client = new AsyncHttpClient();
        try {
            AsyncHttpClient.BoundRequestBuilder builder = client.prepareDelete(url);
            Future<Response> future = builder.execute();
            Response response = future.get();
            return response.getStatusCode();
        } catch (Exception e) {
            return -1;
        } finally {
            client.close();
        }
    }

    @Trace(dispatcher = true)
    public static int makeAsyncRequestHead(String url) {
        AsyncHttpClient client = new AsyncHttpClient();
        try {
            AsyncHttpClient.BoundRequestBuilder builder = client.prepareHead(url);
            Future<Response> future = builder.execute();
            Response response = future.get();
            return response.getStatusCode();
        } catch (Exception e) {
            return -1;
        } finally {
            client.close();
        }
    }

    @Trace(dispatcher = true)
    public static int makeAsyncRequestOptions(String url) {
        AsyncHttpClient client = new AsyncHttpClient();
        try {
            AsyncHttpClient.BoundRequestBuilder builder = client.prepareOptions(url);
            Future<Response> future = builder.execute();
            Response response = future.get();
            return response.getStatusCode();
        } catch (Exception e) {
            return -1;
        } finally {
            client.close();
        }
    }

    @Trace(dispatcher = true)
    public static int makeAsyncRequest(String url) {
        AsyncHttpClient client = new AsyncHttpClient();
        try {
            Request request = new RequestBuilder("get").setUrl(url).build();
            AsyncHttpClient.BoundRequestBuilder builder = client.prepareRequest(request);
            Future<Response> future = builder.execute();
            Response response = future.get();
            return response.getStatusCode();
        } catch (Exception e) {
            return -1;
        } finally {
            client.close();
        }
    }

    @Trace(dispatcher = true)
    private static void makeAsyncExecuteRequest1(String url) {
        AsyncHttpClient client = new AsyncHttpClient();
        try{
            Request request = new RequestBuilder("get").setUrl(url).build();
            Future<Response> f = client.executeRequest(request);
            Response response = f.get();
            response.getStatusCode();
        } catch (InterruptedException | IOException | ExecutionException e) {
        }
    }

    @Trace(dispatcher = true)
    private static void makeAsyncExecuteRequest2(String url) {
        AsyncHttpClient client = new AsyncHttpClient();
        try{
            Request request = new RequestBuilder("get").setUrl(url).build();
            Future<Response> f = client.executeRequest(request, new AsyncCompletionHandler<Response>() {

                @Override
                public Response onCompleted(Response response) {
                    return response;
                }

                @Override
                public void onThrowable(Throwable t) {
                }
            });
            Response response = f.get();
            response.getStatusCode();
        } catch (InterruptedException | IOException | ExecutionException e) {
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
