package com.nr.agent.security.instrumentation.servlet6;

import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.api.agent.security.instrumentation.helpers.URLMappingsHelper;
import com.newrelic.api.agent.security.schema.ApplicationURLMapping;
import org.junit.Assert;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.Iterator;

@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = { "jakarta.servlet", "com.newrelic.agent.security.instrumentation.servlet6" })
public class ServletContainerInitializerTest {
    @ClassRule
    public static HttpServletServer server = new HttpServletServer();

    @Test
    public void testURLMappings() {
        Iterator<ApplicationURLMapping> mappings = URLMappingsHelper.getApplicationURLMappings().iterator();

        Assert.assertTrue("URL Mappings", mappings.hasNext());
        ApplicationURLMapping mapping1 = mappings.next();
        Assert.assertEquals("URL Mappings", new ApplicationURLMapping("*", "/*", HttpTestServlet.class.getName()), mapping1);
    }
}
