package com.nr.agent.security.instrumentation.vertx.core340;

import com.newrelic.agent.security.instrumentation.vertx.VertxClientHelper;
import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.security.schema.operation.SSRFOperation;
import com.newrelic.security.test.marker.*;
import io.vertx.core.AsyncResult;
import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.http.HttpServer;
import io.vertx.core.http.impl.HttpClientRequestImpl;
import io.vertx.ext.web.client.HttpResponse;
import io.vertx.ext.web.client.WebClient;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runner.RunWith;

import java.util.List;
import java.util.concurrent.CountDownLatch;

@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = { "io.vertx.core" })
@FixMethodOrder
@Category({ Java17IncompatibleTest.class, Java21IncompatibleTest.class, Java23IncompatibleTest.class })
public class WebClientTest {
    private static int port;
    private static WebClient webClient;
    private static HttpServer server;
    private static String url;

    @BeforeClass
    public static void beforeClass() {
        port = SecurityInstrumentationTestRunner.getIntrospector().getRandomPort();
        url = "http://localhost:%s/%s";
        webClient = WebClient.create(Vertx.vertx());
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
        webClient.close();
    }

    @Test
    public void testSend() throws InterruptedException {
        CountDownLatch latch = new CountDownLatch(1);
        webClient.get(port, "localhost", "/hi").send(reqHandler(latch));
        latch.await();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        verifySSRFOperation(introspector, String.format(url, port, "hi"));
    }

    @Test
    public void testSend1() throws InterruptedException {
        CountDownLatch latch = new CountDownLatch(1);
        webClient.request(HttpMethod.GET, port, "localhost", "/hi").send(reqHandler(latch));
        latch.await();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        verifySSRFOperation(introspector, String.format(url, port, "hi"));
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
    public void testUnknownHost() {
        webClient.get(port, "notARealHostDuderina.com", "/").send(reqHandler(null));

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        verifySSRFOperation(introspector, String.format("http://notARealHostDuderina.com:%s/", port));
    }

    private Handler<AsyncResult<HttpResponse<Buffer>>> reqHandler(CountDownLatch latch) {
        return response -> {
            System.out.println("Status code : " + response.result().statusCode());
            latch.countDown();
        };
    }
}
