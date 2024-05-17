package com.nr.agent.security.instrumentation.spring.webmvc;

import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.api.agent.security.instrumentation.helpers.URLMappingsHelper;
import com.newrelic.api.agent.security.schema.ApplicationURLMapping;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

import java.util.HashMap;
import java.util.Set;

@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = {"org.springframework.web.servlet"})
public class APIEndpointTest {

    TestHandlerMethodMapping methodMapping = new TestHandlerMethodMapping();


    private final String handler = TestMappings.class.getName();

    private final static HashMap<String, String> map = new HashMap<>();


    @BeforeClass
    public static void addMappings() {
        map.put("/postMapping", "POST");
        map.put("/requestMapping", "GET");
        map.put("/putMapping", "PUT");
        map.put("/deleteMapping", "DELETE");
    }

    @Test
    public void testAPIEndpointDetection() {
        methodMapping.addMapping(new TestMappings());

        Set<ApplicationURLMapping> mappings = URLMappingsHelper.getApplicationURLMappings();
        Assert.assertEquals(4, mappings.size());

        for (ApplicationURLMapping mapping: mappings) {
            Assert.assertNotNull(mapping);
            assertMapping(mapping);
        }

    }

    private void assertMapping(ApplicationURLMapping actualMapping) {
        String path = actualMapping.getPath();
        String method = map.get(path);
        Assert.assertEquals(method, actualMapping.getMethod());
        Assert.assertEquals(handler, actualMapping.getHandler());
    }
}

class TestHandlerMethodMapping extends RequestMappingHandlerMapping {

    public void addMapping(Object handler) {
        super.detectHandlerMethods(handler);
    }
}
