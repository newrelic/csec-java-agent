package com.nr.instrumentation.security.httpclient3;

import com.newrelic.agent.security.introspec.HttpTestServer;
import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.agent.security.introspec.internal.HttpServerRule;
import com.newrelic.api.agent.Trace;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.security.schema.operation.SSRFOperation;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.methods.GetMethod;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.IOException;
import java.net.URISyntaxException;
import java.util.List;

@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = "com.nr.agent.instrumentation.security.httpclient3")
public class HttpClientTest {
    @Rule
    public HttpServerRule server = new HttpServerRule();

    @Test
    public void testExecute() throws URISyntaxException, IOException {
        callExecute();
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        SSRFOperation operation = (SSRFOperation) operations.get(0);
        Assert.assertEquals("Invalid executed parameters.", server.getEndPoint().toString(), operation.getArg());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.HTTP_REQUEST, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
    }

    @Trace(dispatcher = true)
    public void callExecute() throws URISyntaxException, IOException {
        HttpClient httpclient = new HttpClient();

        GetMethod httpget = new GetMethod(server.getEndPoint().toString());
        httpget.setRequestHeader(HttpTestServer.DO_CAT, String.valueOf(true));
        httpclient.executeMethod(httpget);
    }
}
