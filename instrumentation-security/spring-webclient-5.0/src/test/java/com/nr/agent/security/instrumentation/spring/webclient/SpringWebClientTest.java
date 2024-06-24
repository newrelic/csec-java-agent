package com.nr.agent.security.instrumentation.spring.webclient;

import com.newrelic.agent.security.instrumentation.spring.client5.SpringWebClientHelper;
import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.agent.security.introspec.internal.HttpServerRule;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.security.schema.operation.SSRFOperation;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.web.reactive.function.client.WebClient;

import java.net.URI;
import java.util.List;

// Did not add assertions for verifying security headers, as security headers are added to new object of ClientRequest, as ClientRequest object is immutable.
@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = {"org.springframework.web.reactive", "com.newrelic.agent.security.instrumentation"})
@FixMethodOrder
public class SpringWebClientTest {
    @ClassRule
    public static HttpServerRule server = new HttpServerRule();
    private static URI url;

    @BeforeClass
    public static void before() throws Exception{
        // This is here to prevent reactor.util.ConsoleLogger output from taking over your screen
        System.setProperty("reactor.logging.fallback", "JDK");
        url = server.getEndPoint();
    }

    @Test
    public void testExchange() {
        WebClient webClient = WebClient.builder().build();
        webClient.get().uri(url).exchange();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        assertSSRFOperation(introspector);
    }

    @Test
    public void testExchange1() {
        WebClient webClient = WebClient.builder().baseUrl(url.toString()).build();
        webClient.get().exchange();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        assertSSRFOperation(introspector);
    }

    @Test
    public void testExchange2() {
        WebClient webClient = WebClient.builder().baseUrl(url.toString()).build();
        webClient.get().retrieve();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        assertSSRFOperation(introspector);
    }

    @Test
    public void testExchange3() {
        WebClient webClient = WebClient.builder().build();
        webClient.get().uri(url).retrieve();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        assertSSRFOperation(introspector);
    }

    private void assertSSRFOperation(SecurityIntrospector introspector) {
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertEquals("Incorrect no. of operations detected", 1, operations.size());

        Assert.assertTrue(operations.get(0) instanceof SSRFOperation);
        SSRFOperation operation = (SSRFOperation)operations.get(0);
        Assert.assertEquals("Incorrect Vulnerability CaseType detected", VulnerabilityCaseType.HTTP_REQUEST, operation.getCaseType());
        Assert.assertEquals("Incorrect method detected", SpringWebClientHelper.METHOD_EXECHANGE, operation.getMethodName());
        Assert.assertEquals("Incorrect arg detected for SSRF Operation", url.toString(), operation.getArg());
    }
}
