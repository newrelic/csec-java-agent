/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package com.nr.agent.security.instrumentation.vertx.core400;

import com.newrelic.agent.security.instrumentation.vertx.web.VertxClientHelper;
import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.instrumentation.helpers.ServletHelper;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.security.schema.operation.SSRFOperation;
import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
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
@InstrumentationTestConfig(includePrefixes = { "io.vertx.core" })
@FixMethodOrder
public class VertxClientTest {

    private static int port;
    private static HttpClient httpClient;
    private static Future<HttpServer> server;
    private static String url;
    private static final String headerValue = String.valueOf(UUID.randomUUID());
    private static final Vertx vertx = Vertx.vertx();

    @BeforeClass
    public static void beforeClass() {
        port = SecurityInstrumentationTestRunner.getIntrospector().getRandomPort();
        url = "http://localhost:%s/%s";
        server = vertx.createHttpServer().requestHandler(request -> {
            final String statusCode = request.getHeader("statusCode");
            if (statusCode == null) {
                request.response().end("response");
            } else {
                request.response().setStatusCode(Integer.parseInt(statusCode)).end("response");
            }
        }).listen(port);
        httpClient = vertx.createHttpClient();
    }

    @AfterClass
    public static void afterClass() {
        server.result().close();
        httpClient.close();
        vertx.close();
    }

    @Test
    public void testEndMethod() throws InterruptedException {
        CountDownLatch latch = new CountDownLatch(1);
        httpClient.request(HttpMethod.GET, port, "localhost", "/hi", req -> {
            HttpClientRequest result = req.result();
            result.end();
            result.response().onComplete(asyncHandler(latch));
        });
        latch.await();
        VerifySSRFOperation(String.format(url, port, "hi"));
    }
    @Test
    public void testEndMethod1() throws InterruptedException {
        CountDownLatch latch = new CountDownLatch(1);
        httpClient.request(HttpMethod.GET, port, "localhost", "/hi", req -> {
            HttpClientRequest result = req.result();
            result.end("string chunk!");
            result.response().onComplete(asyncHandler(latch));
        });
        latch.await();
        VerifySSRFOperation(String.format(url, port, "hi"));
    }

    @Test
    public void testEndMethod2() throws InterruptedException {
        CountDownLatch latch = new CountDownLatch(1);
        httpClient.request(HttpMethod.GET, port, "localhost", "/hi", result -> {
            if (result.succeeded()) {
                HttpClientRequest req = result.result();
                req.end(Buffer.buffer("string chunk!")); //Sending the request
                req.response().onComplete(asyncHandler(latch));
            }
        });
        latch.await();

        VerifySSRFOperation(String.format(url, port, "hi"));
    }

    @Test
    public void testSendMethod() throws InterruptedException {
        CountDownLatch latch = new CountDownLatch(1);
        httpClient.request(HttpMethod.GET, port, "localhost", "/hi", reqAsyncResult -> {
            if (reqAsyncResult.succeeded()) {   //Request object successfully created
                HttpClientRequest request = reqAsyncResult.result();
                request.send(asyncHandler(latch)); //Sending the request
            }
        });
        latch.await();

        VerifySSRFOperation(String.format(url, port, "hi"));
    }
    @Test
    public void testSendMethod1() throws InterruptedException {
        CountDownLatch latch = new CountDownLatch(1);
        httpClient.request(HttpMethod.GET, port, "localhost", "/hi", result -> {
            if (result.succeeded()) {
                result.result().send() //Sending the request
                        .onComplete(asyncHandler(latch));
            }
        });
        latch.await();

        VerifySSRFOperation(String.format(url, port, "hi"));
    }

    @Test
    public void testSendMethod2() throws InterruptedException {
        CountDownLatch latch = new CountDownLatch(1);
        httpClient.request(HttpMethod.GET, port, "localhost", "/hi", result -> {
            if (result.succeeded()) {
                result.result().send("string body") //Sending the request
                        .onComplete(asyncHandler(latch));
            }
        });
        latch.await();

        VerifySSRFOperation(String.format(url, port, "hi"));
    }

    @Test
    public void testEndMethodCSECHeader() throws InterruptedException {
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        setCSECHeaders(introspector);

        CountDownLatch latch = new CountDownLatch(1);
        Future<HttpClientRequest> request = httpClient.request(HttpMethod.GET, port, "localhost", "/hi");
        request.onComplete(req -> {
            HttpClientRequest result = req.result();
            result.end();
            result.response().onComplete(asyncHandler(latch));
        });
        latch.await();

        VerifySSRFOperation(String.format(url, port, "hi"));
        Assert.assertTrue(request.succeeded());
        verifyHeaders(request.result().headers());
    }

    @Test
    public void testEndMethodCSECHeader1() throws InterruptedException {
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        setCSECHeaders(introspector);

        CountDownLatch latch = new CountDownLatch(1);
        Future<HttpClientRequest> request = httpClient.request(HttpMethod.GET, port, "localhost", "/hi").onComplete(req -> {
            HttpClientRequest result = req.result();
            result.end("string chunk!");
            result.response().onComplete(asyncHandler(latch));
        });
        latch.await();

        VerifySSRFOperation(String.format(url, port, "hi"));
        Assert.assertTrue(request.succeeded());
        verifyHeaders(request.result().headers());
    }

    @Test
    public void testEndMethodCSECHeader2() throws InterruptedException {
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        setCSECHeaders(introspector);

        CountDownLatch latch = new CountDownLatch(1);
        Future<HttpClientRequest> request = httpClient.request(HttpMethod.GET, port, "localhost", "/hi").onComplete(result -> {
            if (result.succeeded()) {
                HttpClientRequest req = result.result();
                req.end(Buffer.buffer("string chunk!")); //Sending the request
                req.response().onComplete(asyncHandler(latch));
            }
        });
        latch.await();

        VerifySSRFOperation(String.format(url, port, "hi"));
        Assert.assertTrue(request.succeeded());
        verifyHeaders(request.result().headers());
    }

    @Test
    public void testSendMethodCSECHeader() throws InterruptedException {
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        setCSECHeaders(introspector);

        CountDownLatch latch = new CountDownLatch(1);
        Future<HttpClientRequest> request = httpClient.request(HttpMethod.GET, port, "localhost", "/hi").onComplete(reqAsyncResult -> {
            if (reqAsyncResult.succeeded()) {   //Request object successfully created
                HttpClientRequest req = reqAsyncResult.result();
                req.send(asyncHandler(latch)); //Sending the request
            }
        });
        latch.await();

        VerifySSRFOperation(String.format(url, port, "hi"));
        Assert.assertTrue(request.succeeded());
        verifyHeaders(request.result().headers());
    }
    @Test
    public void testSendMethodCSECHeader1() throws InterruptedException {
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        setCSECHeaders(introspector);

        CountDownLatch latch = new CountDownLatch(1);
        Future<HttpClientRequest> request = httpClient.request(HttpMethod.GET, port, "localhost", "/hi").onComplete(result -> {
            if (result.succeeded()) {
                result.result().send() //Sending the request
                        .onComplete(asyncHandler(latch));
            }
        });
        latch.await();

        VerifySSRFOperation(String.format(url, port, "hi"));
        Assert.assertTrue(request.succeeded());
        verifyHeaders(request.result().headers());
    }

    @Test
    public void testSendMethodCSECHeader2() throws InterruptedException {
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        setCSECHeaders(introspector);

        CountDownLatch latch = new CountDownLatch(1);
        Future<HttpClientRequest> request = httpClient.request(HttpMethod.GET, port, "localhost", "/hi").onComplete(result -> {
            if (result.succeeded()) {
                result.result().send("string body") //Sending the request
                        .onComplete(asyncHandler(latch));
            }
        });
        latch.await();

        VerifySSRFOperation(String.format(url, port, "hi"));
        Assert.assertTrue(request.succeeded());
        verifyHeaders(request.result().headers());
    }

    private void VerifySSRFOperation(String url) {
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();

        Assert.assertEquals(1, operations.size());
        Assert.assertTrue(operations.get(0) instanceof SSRFOperation);

        SSRFOperation operation = (SSRFOperation) operations.get(0);
        Assert.assertEquals(url, operation.getArg());
        Assert.assertEquals(VertxClientHelper.METHOD_END, operation.getMethodName());
        Assert.assertEquals(HttpClientRequestImpl.class.getName(), operation.getClassName());
        Assert.assertEquals(VulnerabilityCaseType.HTTP_REQUEST, operation.getCaseType());
    }

    private void setCSECHeaders(SecurityIntrospector introspector) {
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

    private Handler<AsyncResult<HttpClientResponse>> asyncHandler(CountDownLatch latch) {
        return respAsyncResult -> {
            HttpClientResponse response = respAsyncResult.result();
            System.out.println("response code : " + response.statusCode());
            latch.countDown();
        };
    }
}
