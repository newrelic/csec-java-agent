package com.nr.instrumentation.urlconnection.test;

import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.api.agent.Trace;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;

@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = "java.net")
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
        URL u = new URL("http://example.com");
        HttpURLConnection conn = (HttpURLConnection) u.openConnection();


        conn.connect();

        InputStream in = conn.getInputStream();
    }
}
