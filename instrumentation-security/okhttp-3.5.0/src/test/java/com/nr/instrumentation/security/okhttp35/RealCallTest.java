package com.nr.instrumentation.security.okhttp35;

import com.newrelic.agent.security.introspec.HttpTestServer;
import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.agent.security.introspec.internal.HttpServerRule;
import com.newrelic.api.agent.Trace;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.security.schema.constants.AgentConstants;
import com.newrelic.api.agent.security.schema.operation.SSRFOperation;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import org.junit.Assert;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.IOException;
import java.net.UnknownHostException;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = { "com.nr.agent.instrumentation.security.okhttp35" })
public class RealCallTest {
    @ClassRule
    public static HttpServerRule server = new HttpServerRule();

    @Test
    public void testExecute() throws Exception {
        String headerValue = String.valueOf(UUID.randomUUID());

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        introspector.setK2FuzzRequestId(headerValue);
        introspector.setK2TracingData(headerValue);

        try {
            httpClientExternal(server.getEndPoint().toString());
        } catch (UnknownHostException e) {
            throw new RuntimeException(e);
        }

        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("No operations detected", operations.size() > 0);
        SSRFOperation operation = (SSRFOperation) operations.get(0);
        Map<String, String> headers = server.getHeaders();

        Assert.assertEquals("Invalid executed parameters.", server.getEndPoint().toString(), operation.getArg());
        Assert.assertEquals("Invalid event category.", VulnerabilityCaseType.HTTP_REQUEST, operation.getCaseType());
        Assert.assertEquals("Invalid executed method name.", "execute", operation.getMethodName());
        Assert.assertTrue(String.format("Missing K2 header: %s", AgentConstants.K2_FUZZ_REQUEST_ID), headers.containsKey(AgentConstants.K2_FUZZ_REQUEST_ID));
        Assert.assertEquals(String.format("Invalid K2 header value for:  %s", AgentConstants.K2_FUZZ_REQUEST_ID), headerValue, headers.get(AgentConstants.K2_FUZZ_REQUEST_ID));
        Assert.assertTrue(String.format("Missing K2 header: %s", AgentConstants.K2_TRACING_DATA), headers.containsKey(AgentConstants.K2_TRACING_DATA.toLowerCase()));
        Assert.assertEquals(String.format("Invalid K2 header value for:  %s", AgentConstants.K2_TRACING_DATA), String.format("%s;DUMMY_UUID/dummy-api-id/dummy-exec-id;",headerValue), headers.get(AgentConstants.K2_TRACING_DATA.toLowerCase()));
    }

    @Trace(dispatcher = true)
    private void httpClientExternal(String host) throws IOException {
        final OkHttpClient client = new OkHttpClient();

        final Request request = new Request.Builder()
                .url(host)
                .addHeader(HttpTestServer.DO_CAT, String.valueOf(true))
                .build();

        Response response = client.newCall(request).execute();
        response.body().close();
    }
}
