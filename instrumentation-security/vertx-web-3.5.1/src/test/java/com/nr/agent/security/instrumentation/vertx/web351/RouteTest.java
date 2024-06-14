package com.nr.agent.security.instrumentation.vertx.web351;

import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.api.agent.security.schema.AgentMetaData;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpServer;
import io.vertx.ext.web.Router;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;

@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = { "io.vertx.ext" })
@FixMethodOrder
public class RouteTest {
    private static int port;
    private static Vertx vertx;
    private static HttpServer server;;
    @BeforeClass
    public static void beforeClass() {
        port = SecurityInstrumentationTestRunner.getIntrospector().getRandomPort();
        vertx = Vertx.vertx();
        Router router = Router.router(vertx);
        router.route().path("/route").handler((context -> context.response().setStatusCode(200).end()));
        server = vertx.createHttpServer().requestHandler(router::accept).listen(port);
    }

    @AfterClass
    public static void afterClass() {
        server.close();
        vertx.close();
    }

    @Test
    public void testEndMethod() throws IOException {
        connect();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        AgentMetaData metaData = introspector.getSecurityMetaData().getMetaData();

        Assert.assertTrue(metaData.isUserLevelServiceMethodEncountered());
        Assert.assertEquals("vertx-web", metaData.getUserLevelServiceMethodEncounteredFramework());
        Assert.assertFalse( metaData.isFoundAnnotedUserLevelServiceMethod());
    }

    private void connect() throws IOException {
        URL u = new URL(String.format("http://localhost:%s/route", port));

        HttpURLConnection conn = (HttpURLConnection) u.openConnection();
        conn.setRequestProperty("content-type", "text/plain; charset=utf-8");
        conn.connect();
        System.out.println("response code : " + conn.getResponseCode());
    }
}
