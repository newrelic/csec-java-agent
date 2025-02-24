package com.nr.agent.security.instrumentation.servlet30;

import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.api.agent.Trace;
import com.newrelic.api.agent.security.instrumentation.helpers.URLMappingsHelper;
import com.newrelic.api.agent.security.schema.ApplicationURLMapping;
import com.newrelic.api.agent.security.schema.Framework;
import com.newrelic.api.agent.security.schema.SecurityMetaData;
import org.junit.Assert;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.Iterator;

@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = { "javax.servlet", "com.newrelic.agent.security.instrumentation.servlet30" })
public class ApiEndpointTest {
    @ClassRule
    public static HttpServletServer server = new HttpServletServer();

    @Test
    public void testURLMappings() {
        String handler = MyServlet.class.getName();
        String method = "*";
        Iterator<ApplicationURLMapping> mappings = URLMappingsHelper.getApplicationURLMappings().iterator();

        Assert.assertTrue("URL Mappings", mappings.hasNext());
        ApplicationURLMapping mapping1 = mappings.next();
        Assert.assertEquals("URL Mappings", new ApplicationURLMapping(method, "/*", handler), mapping1);

        Assert.assertTrue("URL Mappings", mappings.hasNext());
        ApplicationURLMapping mapping2 = mappings.next();
        Assert.assertEquals("URL Mappings", new ApplicationURLMapping(method, "/test", handler), mapping2);
    }

    @Test
    public void testRoute() throws IOException, URISyntaxException {
        connect();
        SecurityMetaData metaData = SecurityInstrumentationTestRunner.getIntrospector().getSecurityMetaData();
        Assert.assertEquals( "Incorrect Route Detected","/test", metaData.getRequest().getRoute());
        Assert.assertEquals("Incorrect Framework detected", Framework.SERVLET.name(), metaData.getMetaData().getFramework());
    }

    @Trace(dispatcher = true)
    private void connect() throws IOException, URISyntaxException {
        URL u = server.getEndPoint().toURL();
        HttpURLConnection conn = (HttpURLConnection) u.openConnection();
        conn.setRequestProperty("content-type", "text/plain; charset=utf-8");
        conn.connect();
        conn.getResponseCode();
    }
}
