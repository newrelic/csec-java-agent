package com.nr.agent.security.instrumentation.spring.webmvc;

import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.api.agent.security.instrumentation.helpers.URLMappingsHelper;
import com.newrelic.api.agent.security.schema.ApplicationURLMapping;
import com.newrelic.api.agent.security.schema.Framework;
import com.newrelic.api.agent.security.schema.SecurityMetaData;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

import javax.servlet.http.HttpServletRequest;
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
    public void testAPIEndpointDetection() throws Exception {
        methodMapping.addMapping(new TestMappings());

        Set<ApplicationURLMapping> mappings = URLMappingsHelper.getApplicationURLMappings();
        Assert.assertEquals(4, mappings.size());

        for (ApplicationURLMapping mapping: mappings) {
            Assert.assertNotNull(mapping);
            // Assertions for URL Mappings
            assertMapping(mapping);

            // Assertions for Route Detection
            assertRouteDetection(mapping);
        }
    }

    private void assertRouteDetection(ApplicationURLMapping mapping) throws Exception {
        methodMapping.handleRequest(new DummyRequest(mapping.getPath(), mapping.getMethod()));

        SecurityMetaData metaData = SecurityInstrumentationTestRunner.getIntrospector().getSecurityMetaData();
        Assert.assertFalse(metaData.getRequest().getRoute().isEmpty());
        Assert.assertEquals(mapping.getPath(), metaData.getRequest().getRoute());

        Assert.assertEquals(Framework.SPRING_WEB_MVC.name(), metaData.getMetaData().getFramework());
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
    public void handleRequest(HttpServletRequest request) throws Exception {
        super.getHandlerInternal(request);
    }
}
