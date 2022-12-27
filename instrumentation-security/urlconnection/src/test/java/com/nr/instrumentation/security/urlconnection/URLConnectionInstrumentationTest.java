package com.nr.instrumentation.security.urlconnection;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.api.agent.Trace;
import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.net.URLConnection;
import java.util.List;

@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = {"com.nr.agent.instrumentation.security.urlconnection.URLConnection_Instrumentation"})
public class URLConnectionInstrumentationTest {
    @Test
    public void testConnect() throws IOException {
        callConnect();

        // Assert the event category and executed parameter
        List<AbstractOperation> operations = NewRelicSecurity.getAgent().getSecurityMetaData().getCustomAttribute("operations", List.class);
        Assert.assertTrue("No operations detected", operations.size() > 0);
        for (AbstractOperation operation : operations) {
            System.out.println("Operation : " + new ObjectMapper().writeValueAsString(operation));
        }
    }

    @Trace(dispatcher = true)
    public void callConnect() throws IOException {
        URL u = new URL("http://google.com");
        URLConnection conn = u.openConnection();
        InputStream in = conn.getInputStream();
    }
}
