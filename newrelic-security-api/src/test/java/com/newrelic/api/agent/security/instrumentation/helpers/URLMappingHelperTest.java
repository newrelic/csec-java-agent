package com.newrelic.api.agent.security.instrumentation.helpers;

import com.newrelic.api.agent.security.schema.ApplicationURLMapping;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class URLMappingHelperTest {

    @Test
    public void testGetApplicationURLMappings() {
        URLMappingsHelper.addApplicationURLMapping(new ApplicationURLMapping("GET","/"));
        URLMappingsHelper.addApplicationURLMapping(new ApplicationURLMapping("GET","/", this.getClass().getName()));
        URLMappingsHelper.addApplicationURLMapping(new ApplicationURLMapping("GET","/{id}"));
        URLMappingsHelper.addApplicationURLMapping(new ApplicationURLMapping("GET","/id/<[0-9]+>"));
        URLMappingsHelper.addApplicationURLMapping(new ApplicationURLMapping("GET","/:id", this.getClass().getName()));
        URLMappingsHelper.addApplicationURLMapping(new ApplicationURLMapping("GET","/$id", this.getClass().getName()));
        Assertions.assertEquals(5, URLMappingsHelper.getApplicationURLMappings().size());
        Assertions.assertEquals(5, URLMappingsHelper.getRouteSegments().size());
        Assertions.assertEquals(1, URLMappingsHelper.getHandlersHash().size());
    }


    @Test
    public void testGetSegments() {
        List<String> segments = new ArrayList<>();
        segments.add("{id}"); segments.add("route"); segments.add("some");
        Assertions.assertEquals(segments, URLMappingsHelper.getSegments("/some/route/{id}"));
        Assertions.assertEquals(segments, URLMappingsHelper.getSegments(" /some/route/{id}"));

        segments.clear(); segments.add("");
        Assertions.assertEquals(Collections.emptyList(), URLMappingsHelper.getSegments(" "));
        Assertions.assertEquals(Collections.emptyList(), URLMappingsHelper.getSegments(""));

        segments.clear(); segments.add("test");
        Assertions.assertEquals(segments, URLMappingsHelper.getSegments("/test"));
    }

    @Test
    public void testGetSegmentsCount() {
        Assertions.assertEquals(3, URLMappingsHelper.getSegmentCount("/some/route/{id}"));
        Assertions.assertEquals(4, URLMappingsHelper.getSegmentCount(" /some/route/{id}"));
        Assertions.assertEquals(1, URLMappingsHelper.getSegmentCount(" "));
        Assertions.assertEquals(0, URLMappingsHelper.getSegmentCount(""));
    }

    @Test
    public void testRemoveApplicationURLMapping() {
        URLMappingsHelper.addApplicationURLMapping(new ApplicationURLMapping("GET","/"));
        URLMappingsHelper.removeApplicationURLMapping("GET", "/");
        Assertions.assertEquals(0, URLMappingsHelper.getApplicationURLMappings().size());
    }

    @Test
    public void testRemoveApplicationURLMapping1() {
        URLMappingsHelper.removeApplicationURLMapping("GET", "/");
        Assertions.assertEquals(4, URLMappingsHelper.getApplicationURLMappings().size());
    }

}
