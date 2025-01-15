package com.nr.agent.security.instrumentation.netty_reactor;

import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.api.agent.Trace;
import com.newrelic.api.agent.security.instrumentation.helpers.URLMappingsHelper;
import com.newrelic.api.agent.security.schema.ApplicationURLMapping;
import com.newrelic.api.agent.security.schema.Framework;
import com.newrelic.api.agent.security.schema.SecurityMetaData;
import io.netty.handler.codec.http.HttpMethod;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import reactor.core.publisher.Mono;
import reactor.netty.DisposableServer;
import reactor.netty.http.server.HttpServer;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = "reactor.netty.http.server")
public class APIEndpointTest {
    private static DisposableServer server;

    private static int PORT;
    @BeforeClass
    public static void beforeClass() {
        PORT = SecurityInstrumentationTestRunner.getIntrospector().getRandomPort();
        server = HttpServer
                .create()
                .host("localhost")
                .port(PORT)
                .route(r -> r
                         .post("/file/{path}", (req, res) -> res.send())
                         .get("/echo/{param}", (req, res) -> res.send())
                         .get("/check", (req, res) -> res.sendString(Mono.just("Check Response data sent...")))
                         .route(
                                 httpServerRequest -> httpServerRequest.uri().equals("/test") && httpServerRequest.method().equals(HttpMethod.GET),
                                 (req, res) -> res.send(req.receive().retain()))
                         .ws("/ws", (req, res) -> res.send(req.receive().retain()))
                         .get("/echo/{param}", (req, res) -> res.send())
                ).bind().block();
    }

    @AfterClass
    public static void afterClass() throws Exception {
        if (server != null){
            server.dispose();
        }
    }

    @Test
    public void apiEndpointTest() {
        String handler = "com.nr.agent.security.instrumentation.netty_reactor.APIEndpointTest$$Lambda$";
        String wsHandler = "reactor.netty.http.server.HttpServerRoutes$$Lambda$";
        Map<String, String> expectedMappings = new HashMap<>();
        expectedMappings.put("/file/{path}", "POST");
        expectedMappings.put("/echo/{param}", "GET");
        expectedMappings.put("/check", "GET");
        expectedMappings.put("/*", "*");
        expectedMappings.put("/ws", "GET");

        Set<ApplicationURLMapping> actualMappings = URLMappingsHelper.getApplicationURLMappings();
        for (ApplicationURLMapping actualMapping : actualMappings) {
            Assert.assertNotNull(actualMapping.getMethod());
            Assert.assertNotNull(actualMapping.getPath());
            Assert.assertNotNull(actualMapping.getHandler());


            Assert.assertEquals(expectedMappings.get(actualMapping.getPath()), actualMapping.getMethod());
            if (!actualMapping.getPath().equals("/ws")) {
                Assert.assertTrue(actualMapping.getHandler().startsWith(handler));
            } else {
                Assert.assertTrue(actualMapping.getHandler().startsWith(wsHandler));
            }
        }
    }

    @Test
    public void routeTest() throws IOException, URISyntaxException {
        service("test");
        SecurityMetaData metaData = SecurityInstrumentationTestRunner.getIntrospector().getSecurityMetaData();
        Assert.assertEquals("/*", metaData.getRequest().getRoute());
        Assert.assertEquals(Framework.NETTY_REACTOR.name(), metaData.getMetaData().getFramework());
    }

    @Test
    public void route1Test() throws IOException, URISyntaxException {
        service("check");
        SecurityMetaData metaData = SecurityInstrumentationTestRunner.getIntrospector().getSecurityMetaData();
        Assert.assertEquals("/check", metaData.getRequest().getRoute());
        Assert.assertEquals(Framework.NETTY_REACTOR.name(), metaData.getMetaData().getFramework());
    }

    @Test
    public void route2Test() throws IOException, URISyntaxException {
        service("echo/name");
        SecurityMetaData metaData = SecurityInstrumentationTestRunner.getIntrospector().getSecurityMetaData();
        Assert.assertEquals("/echo/{param}", metaData.getRequest().getRoute());
        Assert.assertEquals(Framework.NETTY_REACTOR.name(), metaData.getMetaData().getFramework());
    }

    @Trace(dispatcher = true)
    private void service(String path) throws IOException, URISyntaxException {
        URL u = new URL(String.format("http://localhost:%s/%s", PORT, path));
        HttpURLConnection conn = (HttpURLConnection) u.openConnection();

        conn.setRequestProperty("content-type", "text/plain; charset=utf-8");
        conn.setRequestMethod("GET");
        conn.connect();
        System.out.println(conn.getResponseCode());

    }
}
