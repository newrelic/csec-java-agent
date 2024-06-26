package com.nr.agent.security.instrumentation.netty_reactor;

import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.api.agent.security.instrumentation.helpers.URLMappingsHelper;
import com.newrelic.api.agent.security.schema.ApplicationURLMapping;
import io.netty.handler.codec.http.HttpMethod;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import reactor.core.publisher.Mono;
import reactor.ipc.netty.http.server.HttpServer;
import reactor.ipc.netty.tcp.BlockingNettyContext;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = "reactor.ipc.netty.http.server")
public class APIEndpointTest {
    private static BlockingNettyContext server;
    @BeforeClass
    public static void beforeClass() throws Exception {
        server = HttpServer
                .create(SecurityInstrumentationTestRunner.getIntrospector().getRandomPort())
                .startRouter(r -> r
                         .post("/file/{path}", (req, res) -> res.send())
                         .get("/echo/{param}", (req, res) -> res.send())
                         .get("/check", (req, res) -> res.sendString(Mono.just("Check Response data sent...")))
                         .route(
                                 httpServerRequest -> httpServerRequest.uri().equals("/test") && httpServerRequest.method().equals(HttpMethod.GET),
                                 (req, res) -> res.send(req.receive().retain()))
                         .ws("/ws", (req, res) -> res.send(req.receive().retain()))
                         .get("/echo/{param}", (req, res) -> res.send())
                 );
    }

    @AfterClass
    public static void afterClass() throws Exception {
        if (server != null){
            server.shutdown();
        }
    }

    @Test
    public void apiEndpointTest() {
        String handler = "com.nr.agent.security.instrumentation.netty_reactor.APIEndpointTest$$Lambda$";
        String wsHandler = "reactor.ipc.netty.http.server.HttpServerRoutes$$Lambda$";
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
}
