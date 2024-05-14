package com.nr.agent.security.instrumentation.servlet30;

import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.api.agent.security.instrumentation.helpers.URLMappingsHelper;
import com.newrelic.api.agent.security.schema.ApplicationURLMapping;
import org.apache.catalina.servlets.DefaultServlet;
import org.junit.Assert;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;

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
}
