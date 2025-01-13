/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package com.nr.agent.security.instrumentation.vertx.core371;

import com.newrelic.agent.security.instrumentation.vertx.web.VertxClientHelper;
import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.instrumentation.helpers.ServletHelper;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.security.schema.operation.SSRFOperation;
import io.vertx.core.Handler;
import io.vertx.core.MultiMap;
import io.vertx.core.Vertx;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.http.HttpClient;
import io.vertx.core.http.HttpClientRequest;
import io.vertx.core.http.HttpClientResponse;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.http.HttpServer;
import io.vertx.core.http.impl.HttpClientRequestImpl;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;

@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = { "io.vertx.core", "com.newrelic.agent.security.instrumentation.vertx.web" })
@FixMethodOrder
public class VertxClientTest {
    private static int port;
    private static HttpClient httpClient;
    private static HttpServer server;
    private static String url;
    private static String headerValue = String.valueOf(UUID.randomUUID());

    @BeforeClass
    public static void beforeClass() {
        port = SecurityInstrumentationTestRunner.getIntrospector().getRandomPort();
        url = "http://localhost:%s/%s";
        httpClient = Vertx.vertx().createHttpClient();
        server = Vertx.vertx().createHttpServer().requestHandler(request -> {
            final String statusCode = request.getHeader("statusCode");
            if (statusCode == null) {
                request.response().end("response");
            } else {
                request.response().setStatusCode(Integer.parseInt(statusCode)).end("response");
            }
        }).listen(port);
    }

    @AfterClass
    public static void afterClass() {
        server.close();
        httpClient.close();
    }

    @Test
    public void testGetNow() throws InterruptedException {
        CountDownLatch latch = new CountDownLatch(1);
        httpClient.getNow(port, "localhost", "/getNow", reqHandler(latch));
        latch.await();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        verifySSRFOperation(introspector, String.format(url, port, "getNow"));
    }

    @Test
    public void testEndMethod() throws InterruptedException {
        CountDownLatch latch = new CountDownLatch(1);
        httpClient.options(port, "localhost", "/hi").handler(reqHandler(latch)).end();
        latch.await();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        verifySSRFOperation(introspector, String.format(url, port, "hi"));
    }

    @Test
    public void testEndMethod1() throws InterruptedException {
        CountDownLatch latch = new CountDownLatch(1);
        httpClient.request(HttpMethod.GET, port, "localhost", "/hi", reqHandler(latch))
                .end(Buffer.buffer("buffer chunk!"));
        latch.await();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        verifySSRFOperation(introspector, String.format(url, port, "hi"));
    }

    @Test
    public void testEndMethod2() throws InterruptedException {
        CountDownLatch latch = new CountDownLatch(1);
        httpClient.request(HttpMethod.GET, port, "localhost", "/hi", reqHandler(latch))
                .end("string chunk!", "UTF-8");
        latch.await();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        verifySSRFOperation(introspector, String.format(url, port, "hi"));
    }

    @Test
    public void testEndMethod3() throws InterruptedException {
        CountDownLatch latch = new CountDownLatch(1);
        httpClient.request(HttpMethod.GET, port, "localhost", "/hi", reqHandler(latch))
                .end("string chunk!");
        latch.await();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        verifySSRFOperation(introspector, String.format(url, port, "hi"));
    }

    @Test
    public void testEndCSECHeader() throws InterruptedException {
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        setCsecHeaders(introspector);

        CountDownLatch latch = new CountDownLatch(1);
        HttpClientRequest request = httpClient.options(port, "localhost", "/hi");
        request.handler(reqHandler(latch));
        request.resume();
        request.end();
        latch.await();

        verifySSRFOperation(introspector, String.format(url, port, "hi"));
        verifyHeaders(request.headers());
    }

    @Test
    public void testEndCSECHeader1() throws InterruptedException {
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        setCsecHeaders(introspector);

        CountDownLatch latch = new CountDownLatch(1);
        HttpClientRequest request = httpClient.request(HttpMethod.GET, port, "localhost", "/hi", reqHandler(latch));
        request.end(Buffer.buffer("buffer chunk!"));
        latch.await();

        verifySSRFOperation(introspector, String.format(url, port, "hi"));
        verifyHeaders(request.headers());
    }

    @Test
    public void testEndCSECHeader2() throws InterruptedException {
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        setCsecHeaders(introspector);

        CountDownLatch latch = new CountDownLatch(1);
        HttpClientRequest request = httpClient.request(HttpMethod.GET, port, "localhost", "/hi", reqHandler(latch));
        request.end("string chunk!", "UTF-8");
        latch.await();

        verifySSRFOperation(introspector, String.format(url, port, "hi"));
        verifyHeaders(request.headers());
    }

    @Test
    public void testUnknownHost() {
        httpClient.options(port, "notARealHostDuderina.com", "/").handler(reqHandler(null)).end();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        verifySSRFOperation(introspector, String.format("http://notARealHostDuderina.com:%s/", port));
    }

    private void verifySSRFOperation(SecurityIntrospector introspector, String url) {
        List<AbstractOperation> operations = introspector.getOperations();

        Assert.assertEquals(1, operations.size());
        Assert.assertTrue(operations.get(0) instanceof SSRFOperation);

        SSRFOperation operation = (SSRFOperation) operations.get(0);
        Assert.assertEquals(url, operation.getArg());
        Assert.assertEquals(VertxClientHelper.METHOD_END, operation.getMethodName());
        Assert.assertEquals(HttpClientRequestImpl.class.getName(), operation.getClassName());
        Assert.assertEquals(VulnerabilityCaseType.HTTP_REQUEST, operation.getCaseType());
    }

    @Test
    public void testEndMethodHeader3() throws InterruptedException {
        CountDownLatch latch = new CountDownLatch(1);
        HttpClientRequest request = httpClient.request(HttpMethod.GET, port, "localhost", "/hi", reqHandler(latch));
        request.end("string chunk!");
        latch.await();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        verifySSRFOperation(introspector, String.format(url, port, "hi"));
    }

    private Handler<HttpClientResponse> reqHandler(CountDownLatch latch) {
        return response -> {
            System.out.println("Status code : " + response.statusCode());
            latch.countDown();
        };
    }

    private void setCsecHeaders(SecurityIntrospector introspector) {
        introspector.setK2FuzzRequestId(headerValue);
        introspector.setK2ParentId(headerValue);
        introspector.setK2TracingData(headerValue);
    }

    private void verifyHeaders(MultiMap headers) {
        Assert.assertTrue(String.format("Missing K2 header: %s", ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID), headers.contains(ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID));
        Assert.assertEquals(String.format("Invalid K2 header value for:  %s", ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID), headerValue, headers.get(ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID));
        Assert.assertTrue(String.format("Missing K2 header: %s", GenericHelper.CSEC_PARENT_ID), headers.contains(GenericHelper.CSEC_PARENT_ID));
        Assert.assertEquals(String.format("Invalid K2 header value for:  %s", GenericHelper.CSEC_PARENT_ID), headerValue, headers.get(GenericHelper.CSEC_PARENT_ID));
        Assert.assertTrue(String.format("Missing K2 header: %s", ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER), headers.contains(ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER.toLowerCase()));
        Assert.assertEquals(String.format("Invalid K2 header value for:  %s", ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER), String.format("%s;DUMMY_UUID/dummy-api-id/dummy-exec-id;",
                headerValue), headers.get(
                ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER.toLowerCase()));
    }
}
