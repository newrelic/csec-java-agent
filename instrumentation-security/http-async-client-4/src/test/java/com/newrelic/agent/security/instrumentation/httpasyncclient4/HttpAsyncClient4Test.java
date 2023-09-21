package com.newrelic.agent.security.instrumentation.httpasyncclient4;

import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.agent.security.introspec.internal.HttpServerRule;
import com.newrelic.api.agent.Trace;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.security.schema.operation.SSRFOperation;
import org.apache.http.HttpHost;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.client.utils.URIUtils;
import org.apache.http.impl.nio.client.CloseableHttpAsyncClient;
import org.apache.http.impl.nio.client.HttpAsyncClients;
import org.apache.http.nio.client.methods.HttpAsyncMethods;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import java.util.concurrent.Future;

@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = "com.newrelic.agent.security.instrumentation.httpasyncclient4")
public class HttpAsyncClient4Test {
    @ClassRule
    public static HttpServerRule server = new HttpServerRule();

    private static URI endpoint = null;
    @BeforeClass
    public static void before() {
        try {
            endpoint = server.getEndPoint();
        } catch (URISyntaxException e) {
            e.printStackTrace();
        }
    }
    @Test
    public void testExecute() throws Exception {
        callExecute();
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);

        SSRFOperation operation = (SSRFOperation) operations.get(0);
        Assert.assertEquals("Invalid executed parameters.", endpoint.toString(), operation.getArg());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.HTTP_REQUEST, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
    }

    @Test
    public void testExecute1() throws Exception {
        callExecute1();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        SSRFOperation operation = (SSRFOperation) operations.get(0);
        Assert.assertEquals("Invalid executed parameters.", endpoint.toString(), operation.getArg());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.HTTP_REQUEST, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
    }

    @Test
    public void testExecute2() throws Exception {
        callExecute2();
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        SSRFOperation operation = (SSRFOperation) operations.get(0);
        Assert.assertEquals("Invalid executed parameters.", endpoint.toString(), operation.getArg());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.HTTP_REQUEST, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
    }

    @Test
    public void testExecute3() throws Exception {
        callExecute3();
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        SSRFOperation operation = (SSRFOperation) operations.get(0);
        Assert.assertEquals("Invalid executed parameters.", endpoint.toString(), operation.getArg());
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
        Assert.assertEquals("Invalid executed parameters.", endpoint.toString(), operation.getArg());
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
        Assert.assertEquals("Invalid executed parameters.", endpoint.toString(), operation.getArg());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.HTTP_REQUEST, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
    }

    @Trace(dispatcher = true)
    public void callExecute() throws Exception {
        try (CloseableHttpAsyncClient httpclient = HttpAsyncClients.createDefault()) {
            httpclient.start();

            HttpGet request = new HttpGet(endpoint.toString());
            HttpHost target = URIUtils.extractHost(request.getURI());
            Future<HttpResponse> future =
            httpclient.execute(
                    HttpAsyncMethods.create(target, request),
                    HttpAsyncMethods.createConsumer(),
                    HttpClientContext.create(),
                    null);
            future.get();
        }

    }
    @Trace(dispatcher = true)
    public void callExecute1() throws Exception {
        try (CloseableHttpAsyncClient httpclient = HttpAsyncClients.createDefault()) {
            httpclient.start();

            HttpGet request = new HttpGet(endpoint.toString());
            HttpHost target = URIUtils.extractHost(request.getURI());

            Future<HttpResponse> future = httpclient.execute(
                    HttpAsyncMethods.create(target, request),
                    HttpAsyncMethods.createConsumer(),
                    null);
            future.get();
        }
    }

    @Trace(dispatcher = true)
    public void callExecute2() throws Exception {
        try (CloseableHttpAsyncClient httpclient = HttpAsyncClients.createDefault()) {
            httpclient.start();

            HttpGet request = new HttpGet(endpoint.toString());
            HttpHost target = URIUtils.extractHost(request.getURI());

            Future<HttpResponse> future = httpclient.execute(target, request, HttpClientContext.create(), null);
            future.get();
        }
    }

    @Trace(dispatcher = true)
    public void callExecute3() throws Exception {
        try (CloseableHttpAsyncClient httpclient = HttpAsyncClients.createDefault()) {
            httpclient.start();

            HttpGet request = new HttpGet(endpoint.toString());
            HttpHost target = URIUtils.extractHost(request.getURI());

            Future<HttpResponse> future = httpclient.execute(target, request, null);
            future.get();
        }
    }

    @Trace(dispatcher = true)
    public void callExecute4() throws Exception {
        try (CloseableHttpAsyncClient httpclient = HttpAsyncClients.createDefault()) {
            httpclient.start();

            HttpGet request = new HttpGet(endpoint.toString());

            Future<HttpResponse> future = httpclient.execute(request, HttpClientContext.create(),null);
            future.get();
        }
    }

    @Trace(dispatcher = true)
    public void callExecute5() throws Exception {
        try (CloseableHttpAsyncClient httpclient = HttpAsyncClients.createDefault()) {
            httpclient.start();

            HttpGet request = new HttpGet(endpoint.toString());

            Future<HttpResponse> future = httpclient.execute(request,null);
            future.get();
        }
    }
}
