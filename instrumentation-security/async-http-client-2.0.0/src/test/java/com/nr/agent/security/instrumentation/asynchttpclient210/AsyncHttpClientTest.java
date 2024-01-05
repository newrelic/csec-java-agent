package com.nr.agent.security.instrumentation.asynchttpclient210;

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
import com.newrelic.security.test.marker.Java11IncompatibleTest;
import com.newrelic.security.test.marker.Java17IncompatibleTest;
import com.newrelic.agent.security.instrumentation.org.asynchttpclient.AsynchttpHelper;
import org.asynchttpclient.*;
import org.junit.Assert;
import org.junit.FixMethodOrder;
import org.junit.Rule;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;

import java.io.IOException;
import java.net.URISyntaxException;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

@Category({ Java11IncompatibleTest.class, Java17IncompatibleTest.class })
@RunWith(SecurityInstrumentationTestRunner.class)
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@InstrumentationTestConfig(includePrefixes = {"org.asynchttpclient", "com.newrelic.agent.security.instrumentation.org.asynchttpclient"})
public class AsyncHttpClientTest {

    @Rule
    public HttpServerRule server = new HttpServerRule();

    @Test
    public void testExecuteGet() throws URISyntaxException, IOException {
        String headerValue = String.valueOf(UUID.randomUUID());

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        setCSECHeaders(headerValue, introspector);

        makeAsyncRequestGet(server.getEndPoint().toURL().toString());

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        assertEquals("Invalid number of operations detected", 1, operations.size());
        SSRFOperation operation = (SSRFOperation) operations.get(0);
        Map<String, String> headers = server.getHeaders();
        Assert.assertEquals("Invalid executed parameters.", server.getEndPoint().toString(), operation.getArg());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.HTTP_REQUEST, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", AsynchttpHelper.METHOD_EXECUTE, operation.getMethodName());
        verifyHeaders(headerValue, headers);
    }

    @Test
    public void testExecutePost() throws URISyntaxException, IOException {
        String headerValue = String.valueOf(UUID.randomUUID());

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        setCSECHeaders(headerValue, introspector);

        makeAsyncRequestPost(server.getEndPoint().toURL().toString());

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        assertEquals("Invalid number of operations detected", 1, operations.size());
        SSRFOperation operation = (SSRFOperation) operations.get(0);
        Map<String, String> headers = server.getHeaders();
        Assert.assertEquals("Invalid executed parameters.", server.getEndPoint().toString(), operation.getArg());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.HTTP_REQUEST, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", AsynchttpHelper.METHOD_EXECUTE, operation.getMethodName());
        verifyHeaders(headerValue, headers);
    }

    @Test
    public void testExecutePut() throws URISyntaxException, IOException {
        String headerValue = String.valueOf(UUID.randomUUID());

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        setCSECHeaders(headerValue, introspector);

        makeAsyncRequestPut(server.getEndPoint().toURL().toString());

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        assertEquals("Invalid number of operations detected", 1, operations.size());
        SSRFOperation operation = (SSRFOperation) operations.get(0);
        Map<String, String> headers = server.getHeaders();
        Assert.assertEquals("Invalid executed parameters.", server.getEndPoint().toString(), operation.getArg());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.HTTP_REQUEST, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", AsynchttpHelper.METHOD_EXECUTE, operation.getMethodName());
        verifyHeaders(headerValue, headers);
    }

    @Test
    public void testExecuteDelete() throws URISyntaxException, IOException {
        String headerValue = String.valueOf(UUID.randomUUID());

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        setCSECHeaders(headerValue, introspector);

        makeAsyncRequestDelete(server.getEndPoint().toURL().toString());

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        assertEquals("Invalid number of operations detected", 1, operations.size());
        SSRFOperation operation = (SSRFOperation) operations.get(0);
        Map<String, String> headers = server.getHeaders();
        Assert.assertEquals("Invalid executed parameters.", server.getEndPoint().toString(), operation.getArg());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.HTTP_REQUEST, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", AsynchttpHelper.METHOD_EXECUTE, operation.getMethodName());
        verifyHeaders(headerValue, headers);
    }

    @Test
    public void testExecuteHead() throws URISyntaxException, IOException {
        String headerValue = String.valueOf(UUID.randomUUID());

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        setCSECHeaders(headerValue, introspector);

        makeAsyncRequestHead(server.getEndPoint().toURL().toString());

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        assertEquals("Invalid number of operations detected", 1, operations.size());
        SSRFOperation operation = (SSRFOperation) operations.get(0);
        Map<String, String> headers = server.getHeaders();
        Assert.assertEquals("Invalid executed parameters.", server.getEndPoint().toString(), operation.getArg());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.HTTP_REQUEST, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", AsynchttpHelper.METHOD_EXECUTE, operation.getMethodName());
        verifyHeaders(headerValue, headers);
    }

    @Test
    public void testExecuteOptions() throws URISyntaxException, IOException {
        String headerValue = String.valueOf(UUID.randomUUID());

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        setCSECHeaders(headerValue, introspector);

        makeAsyncRequestOptions(server.getEndPoint().toURL().toString());

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        assertEquals("Invalid number of operations detected", 1, operations.size());
        SSRFOperation operation = (SSRFOperation) operations.get(0);
        Map<String, String> headers = server.getHeaders();
        Assert.assertEquals("Invalid executed parameters.", server.getEndPoint().toString(), operation.getArg());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.HTTP_REQUEST, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", AsynchttpHelper.METHOD_EXECUTE, operation.getMethodName());
        verifyHeaders(headerValue, headers);
    }

    @Test
    public void testExecuteConnect() throws URISyntaxException, IOException, InterruptedException {
        String headerValue = String.valueOf(UUID.randomUUID());

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        setCSECHeaders(headerValue, introspector);
        server.getHeaders().clear();
        makeAsyncRequestConnect(server.getEndPoint().toURL().toString());

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        assertEquals("Invalid number of operations detected", 1, operations.size());
        SSRFOperation operation = (SSRFOperation) operations.get(0);
        Map<String, String> headers = server.getHeaders();
        Assert.assertEquals("Invalid executed parameters.", server.getEndPoint().toString(), operation.getArg());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.HTTP_REQUEST, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", AsynchttpHelper.METHOD_EXECUTE, operation.getMethodName());
        Assert.assertFalse(String.format("Unexpected K2 header: %s", ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID), headers.containsKey(ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID));
        Assert.assertFalse(String.format("Unexpected K2 header: %s", GenericHelper.CSEC_PARENT_ID), headers.containsKey(GenericHelper.CSEC_PARENT_ID));
        Assert.assertFalse(String.format("Unexpected K2 header: %s", ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER), headers.containsKey(ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER.toLowerCase()));
    }

    @Test
    public void testExecuteRequest() throws URISyntaxException, IOException {
        String headerValue = String.valueOf(UUID.randomUUID());

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        setCSECHeaders(headerValue, introspector);

        makeAsyncRequest(server.getEndPoint().toURL().toString());

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        assertEquals("Invalid number of operations detected", 1, operations.size());
        SSRFOperation operation = (SSRFOperation) operations.get(0);
        Map<String, String> headers = server.getHeaders();
        Assert.assertEquals("Invalid executed parameters.", server.getEndPoint().toString(), operation.getArg());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.HTTP_REQUEST, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", AsynchttpHelper.METHOD_EXECUTE, operation.getMethodName());
        verifyHeaders(headerValue, headers);
    }

    @Test
    public void testExecuteRequestBuilder() throws URISyntaxException, IOException {
        String headerValue = String.valueOf(UUID.randomUUID());

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        setCSECHeaders(headerValue, introspector);

        makeAsyncRequestBuilder(server.getEndPoint().toURL().toString());

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        assertEquals("Invalid number of operations detected", 1, operations.size());
        SSRFOperation operation = (SSRFOperation) operations.get(0);
        Map<String, String> headers = server.getHeaders();
        Assert.assertEquals("Invalid executed parameters.", server.getEndPoint().toString(), operation.getArg());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.HTTP_REQUEST, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", AsynchttpHelper.METHOD_EXECUTE, operation.getMethodName());
        verifyHeaders(headerValue, headers);
    }

    @Test
    public void testExecuteTrace() throws URISyntaxException, IOException {
        String headerValue = String.valueOf(UUID.randomUUID());

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        setCSECHeaders(headerValue, introspector);

        makeAsyncRequestTrace(server.getEndPoint().toURL().toString());

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        assertEquals("Invalid number of operations detected", 1, operations.size());
        SSRFOperation operation = (SSRFOperation) operations.get(0);
        Map<String, String> headers = server.getHeaders();
        Assert.assertEquals("Invalid executed parameters.", server.getEndPoint().toString(), operation.getArg());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.HTTP_REQUEST, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", AsynchttpHelper.METHOD_EXECUTE, operation.getMethodName());
        verifyHeaders(headerValue, headers);
    }

    @Test
    public void testExecute1() throws URISyntaxException, IOException {
        String headerValue = String.valueOf(UUID.randomUUID());

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        setCSECHeaders(headerValue, introspector);

        makeAsyncRequest1(server.getEndPoint().toURL().toString());

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        assertEquals("Invalid number of operations detected", 1, operations.size());
        SSRFOperation operation = (SSRFOperation) operations.get(0);
        Map<String, String> headers = server.getHeaders();
        Assert.assertEquals("Invalid executed parameters.", server.getEndPoint().toString(), operation.getArg());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.HTTP_REQUEST, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", AsynchttpHelper.METHOD_EXECUTE, operation.getMethodName());
        verifyHeaders(headerValue, headers);
    }

    @Test
    public void testExecute2() throws URISyntaxException, IOException {
        String headerValue = String.valueOf(UUID.randomUUID());

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        setCSECHeaders(headerValue, introspector);

        makeAsyncRequest2(server.getEndPoint().toURL().toString());

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        assertEquals("Invalid number of operations detected", 1, operations.size());
        SSRFOperation operation = (SSRFOperation) operations.get(0);
        Map<String, String> headers = server.getHeaders();
        Assert.assertEquals("Invalid executed parameters.", server.getEndPoint().toString(), operation.getArg());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.HTTP_REQUEST, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", AsynchttpHelper.METHOD_EXECUTE, operation.getMethodName());
        verifyHeaders(headerValue, headers);
    }

    @Test
    public void testExecute3() throws URISyntaxException, IOException {
        String headerValue = String.valueOf(UUID.randomUUID());

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        setCSECHeaders(headerValue, introspector);

        makeAsyncRequest3(server.getEndPoint().toURL().toString());

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        assertEquals("Invalid number of operations detected", 1, operations.size());
        SSRFOperation operation = (SSRFOperation) operations.get(0);
        Map<String, String> headers = server.getHeaders();
        Assert.assertEquals("Invalid executed parameters.", server.getEndPoint().toString(), operation.getArg());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.HTTP_REQUEST, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", AsynchttpHelper.METHOD_EXECUTE, operation.getMethodName());
        verifyHeaders(headerValue, headers);
    }

    @Test
    public void testExecute4() throws URISyntaxException, IOException {
        String headerValue = String.valueOf(UUID.randomUUID());

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        setCSECHeaders(headerValue, introspector);

        makeAsyncRequest4(server.getEndPoint().toURL().toString());

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        assertEquals("Invalid number of operations detected", 1, operations.size());
        SSRFOperation operation = (SSRFOperation) operations.get(0);
        Map<String, String> headers = server.getHeaders();
        Assert.assertEquals("Invalid executed parameters.", server.getEndPoint().toString(), operation.getArg());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.HTTP_REQUEST, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", AsynchttpHelper.METHOD_EXECUTE, operation.getMethodName());
        verifyHeaders(headerValue, headers);
    }

    @Trace(dispatcher = true)
    private static void makeAsyncRequestGet(String url) {
        DefaultAsyncHttpClientConfig.Builder clientBuilder = Dsl.config()
                .setConnectTimeout(500);

        try (AsyncHttpClient client = Dsl.asyncHttpClient(clientBuilder)) {
            BoundRequestBuilder builder = client.prepareGet(url);
            Future<Response> future = builder.execute();
            Response response = future.get();
            response.getStatusCode();
        } catch (Exception e) {
        }
    }

    @Trace(dispatcher = true)
    private static void makeAsyncRequestPost(String url) {
        DefaultAsyncHttpClientConfig.Builder clientBuilder = Dsl.config()
                .setConnectTimeout(500);

        try (AsyncHttpClient client = Dsl.asyncHttpClient(clientBuilder)) {
            BoundRequestBuilder builder = client.preparePost(url);
            Future<Response> future = builder.execute();
            Response response = future.get();
            response.getStatusCode();
        } catch (Exception e) {
        }
    }

    @Trace(dispatcher = true)
    private static void makeAsyncRequestPut(String url) {
        DefaultAsyncHttpClientConfig.Builder clientBuilder = Dsl.config()
                .setConnectTimeout(500);

        try (AsyncHttpClient client = Dsl.asyncHttpClient(clientBuilder)) {
            BoundRequestBuilder builder = client.preparePut(url);
            Future<Response> future = builder.execute();
            Response response = future.get();
            response.getStatusCode();
        } catch (Exception e) {
        }
    }

    @Trace(dispatcher = true)
    private static void makeAsyncRequestDelete(String url) {
        DefaultAsyncHttpClientConfig.Builder clientBuilder = Dsl.config()
                .setConnectTimeout(500);

        try (AsyncHttpClient client = Dsl.asyncHttpClient(clientBuilder)) {
            BoundRequestBuilder builder = client.prepareDelete(url);
            Future<Response> future = builder.execute();
            Response response = future.get();
            response.getStatusCode();
        } catch (Exception e) {
        }
    }

    @Trace(dispatcher = true)
    private static void makeAsyncRequestHead(String url) {
        DefaultAsyncHttpClientConfig.Builder clientBuilder = Dsl.config()
                .setConnectTimeout(500);

        try (AsyncHttpClient client = Dsl.asyncHttpClient(clientBuilder)) {
            BoundRequestBuilder builder = client.prepareHead(url);
            Future<Response> future = builder.execute();
            Response response = future.get();
            response.getStatusCode();
        } catch (Exception e) {
        }
    }

    @Trace(dispatcher = true)
    private static void makeAsyncRequestOptions(String url) {
        DefaultAsyncHttpClientConfig.Builder clientBuilder = Dsl.config()
                .setConnectTimeout(500);

        try (AsyncHttpClient client = Dsl.asyncHttpClient(clientBuilder)) {
            BoundRequestBuilder builder = client.prepareOptions(url);
            Future<Response> future = builder.execute();
            Response response = future.get();
            response.getStatusCode();
        } catch (Exception e) {
        }
    }

    @Trace(dispatcher = true)
    private static void makeAsyncRequestConnect(String url) {
        DefaultAsyncHttpClientConfig.Builder clientBuilder = Dsl.config()
                .setConnectTimeout(500);

        try (AsyncHttpClient client = Dsl.asyncHttpClient(clientBuilder)) {
            BoundRequestBuilder builder = client.prepareConnect(url);
            Future<Response> future = builder.execute();
//            future.get();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Trace(dispatcher = true)
    private static void makeAsyncRequest(String url) {
        DefaultAsyncHttpClientConfig.Builder clientBuilder = Dsl.config()
                .setConnectTimeout(500);

        try (AsyncHttpClient client = Dsl.asyncHttpClient(clientBuilder)) {
            RequestBuilder requestBuilder = new RequestBuilder();
            requestBuilder.setUrl(url);
            BoundRequestBuilder builder = client.prepareRequest(requestBuilder.build());
            Future<Response> future = builder.execute();
            Response response = future.get();
            response.getStatusCode();
        } catch (Exception e) {
        }
    }

    @Trace(dispatcher = true)
    private static void makeAsyncRequestBuilder(String url) {
        DefaultAsyncHttpClientConfig.Builder clientBuilder = Dsl.config()
                .setConnectTimeout(500);

        try (AsyncHttpClient client = Dsl.asyncHttpClient(clientBuilder)) {
            RequestBuilder requestBuilder = new RequestBuilder();
            requestBuilder.setUrl(url);
            BoundRequestBuilder builder = client.prepareRequest(requestBuilder);
            Future<Response> future = builder.execute();
            Response response = future.get();
            response.getStatusCode();
        } catch (Exception e) {
        }
    }

    @Trace(dispatcher = true)
    private static void makeAsyncRequestTrace(String url) {
        DefaultAsyncHttpClientConfig.Builder clientBuilder = Dsl.config()
                .setConnectTimeout(500);

        try (AsyncHttpClient client = Dsl.asyncHttpClient(clientBuilder)) {
            BoundRequestBuilder builder = client.prepareTrace(url);
            Future<Response> future = builder.execute();
            Response response = future.get();
            response.getStatusCode();
        } catch (Exception e) {
        }
    }

    @Trace(dispatcher = true)
    private static void makeAsyncRequest1(String url) {
        try(AsyncHttpClient client = new DefaultAsyncHttpClient()){
            RequestBuilder requestBuilder = new RequestBuilder();
            requestBuilder.setUrl(url);
            ListenableFuture<Response> future = client.executeRequest(requestBuilder.build());
            Response response = null;
            response = future.get();
            response.getStatusCode();
        } catch (InterruptedException | ExecutionException | IOException e) {
        }
    }

    @Trace(dispatcher = true)
    private static void makeAsyncRequest2(String url) {
        try(AsyncHttpClient client = new DefaultAsyncHttpClient(new DefaultAsyncHttpClientConfig.Builder().build())){
            RequestBuilder requestBuilder = new RequestBuilder();
            requestBuilder.setUrl(url);
            ListenableFuture<Response> future = client.executeRequest(requestBuilder);
            Response response = null;
            response = future.get();
            response.getStatusCode();
        } catch (InterruptedException | ExecutionException | IOException e) {
        }
    }

    @Trace(dispatcher = true)
    private static void makeAsyncRequest3(String url) {
        try(AsyncHttpClient client = new DefaultAsyncHttpClient(new DefaultAsyncHttpClientConfig.Builder().build())){
            RequestBuilder requestBuilder = new RequestBuilder();
            requestBuilder.setUrl(url);
            Future<Response> f = client.executeRequest(requestBuilder.build(), new AsyncCompletionHandler<Response>() {

                @Override
                public Response onCompleted(Response response) throws IOException {
                    return response;
                }

                @Override
                public void onThrowable(Throwable t) {
                }
            });
            Response response = f.get();
            response.getStatusCode();
        } catch (InterruptedException | ExecutionException | IOException e) {
        }
    }

    @Trace(dispatcher = true)
    private static void makeAsyncRequest4(String url) {
        try(AsyncHttpClient client = new DefaultAsyncHttpClient(new DefaultAsyncHttpClientConfig.Builder().build())){
            RequestBuilder requestBuilder = new RequestBuilder();
            requestBuilder.setUrl(url);
            Future<Response> f = client.executeRequest(requestBuilder, new AsyncCompletionHandler<Response>() {

                @Override
                public Response onCompleted(Response response) throws IOException {
                    return response;
                }

                @Override
                public void onThrowable(Throwable t) {
                }
            });
            Response response = f.get();
            response.getStatusCode();
        } catch (InterruptedException | ExecutionException | IOException e) {
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
