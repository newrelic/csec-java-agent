package com.nr.instrumentation.security.urlconnection;

import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.api.agent.Trace;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.net.URLConnection;

@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = {"java.net.URLConnection", "com.nr.agent.instrumentation.security.urlconnection.Helper"}, configName = "distributed_tracing.yml")
public class URLConnectionTest {
    @Test
    public void testConnect() throws IOException {
        //with or without it I have the same result
        callConnect();
//        int b;
//        while ((b = in.read()) != -1) {
//            System.out.write(b);
//        }
        // Call Name function
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        System.out.println(introspector.getOperations().hasNext());
    }

    @Trace(dispatcher = true)
    public void callConnect() throws IOException {
        URL u = new URL("http://google.com");
        URLConnection conn = u.openConnection();


        conn.connect();

        InputStream in = conn.getInputStream();
    }
}
