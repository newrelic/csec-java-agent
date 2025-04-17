package com.newrelic.api.agent.security.instrumentation.helpers;

import com.newrelic.api.agent.security.schema.RouteSegments;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.Set;
import java.util.TreeSet;

public class RouteComparatorTest {

    @Test
    public void testCompare() {
        RouteSegments r1 = new RouteSegments("/route1", null);
        RouteSegments r2 = new RouteSegments("/route2", null);

        Assertions.assertTrue(new RouteComparator().compare(r1, r2) > 0);
    }

    @Test
    public void testCompare1() {
        RouteSegments r1 = new RouteSegments("/route12", null);
        RouteSegments r2 = new RouteSegments("/route2", null);

        Assertions.assertTrue(new RouteComparator().compare(r1, r2) < 0);
    }

    @Test
    public void testCompare2() {
        RouteSegments r1 = new RouteSegments("/route12", null);
        RouteSegments r2 = new RouteSegments("/route12", null);

        Assertions.assertEquals(0, new RouteComparator().compare(r1, r2));
    }

}
