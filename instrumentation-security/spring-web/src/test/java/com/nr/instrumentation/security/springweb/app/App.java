/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */
package com.nr.instrumentation.security.springweb.app;

import com.newrelic.api.agent.Trace;

public class App {

    @Trace(dispatcher = true)
    public static String requestMapping() {
        try {
            TestMappings path = new TestMappings();
            return path.testRequest();
        } catch (RuntimeException caught) {
            System.out.printf("Caught exception");
        }
        return null;
    }

    @Trace(dispatcher = true)
    public static String getMapping() {
        try {
            TestMappings path = new TestMappings();
            return path.testGet();
        } catch (RuntimeException caught) {
            System.out.printf("Caught exception");
        }
        return null;
    }

    @Trace(dispatcher = true)
    public static String postMapping() {
        try {
            TestMappings path = new TestMappings();
            return path.testPost();
        } catch (RuntimeException caught) {
            System.out.printf("Caught exception");
        }
        return null;
    }

    @Trace(dispatcher = true)
    public static String patchMapping() {
        try {
            TestMappings path = new TestMappings();
            return path.testPatch();
        } catch (RuntimeException caught) {
            System.out.printf("Caught exception");
        }
        return null;
    }

    @Trace(dispatcher = true)
    public static String putMapping() {
        try {
            TestMappings path = new TestMappings();
            return path.testPut();
        } catch (RuntimeException caught) {
            System.out.printf("Caught exception");
        }
        return null;
    }

    @Trace(dispatcher = true)
    public static String deleteMapping() {
        try {
            TestMappings path = new TestMappings();
            return path.testDelete();
        } catch (RuntimeException caught) {
            System.out.printf("Caught exception");
        }
        return null;
    }

    @Trace(dispatcher = true)
    public static String requestMappingWithRest() {
        try {
            TestMappingsWithRest path = new TestMappingsWithRest();
            return path.testRequest();
        } catch (RuntimeException caught) {
            System.out.printf("Caught exception");
        }
        return null;
    }

    @Trace(dispatcher = true)
    public static String getMappingWithRest() {
        try {
            TestMappingsWithRest path = new TestMappingsWithRest();
            return path.testGet();
        } catch (RuntimeException caught) {
            System.out.printf("Caught exception");
        }
        return null;
    }

    @Trace(dispatcher = true)
    public static String postMappingWithRest() {
        try {
            TestMappingsWithRest path = new TestMappingsWithRest();
            return path.testPost();
        } catch (RuntimeException caught) {
            System.out.printf("Caught exception");
        }
        return null;
    }

    @Trace(dispatcher = true)
    public static String patchMappingWithRest() {
        try {
            TestMappingsWithRest path = new TestMappingsWithRest();
            return path.testPatch();
        } catch (RuntimeException caught) {
            System.out.printf("Caught exception");
        }
        return null;
    }

    @Trace(dispatcher = true)
    public static String putMappingWithRest() {
        try {
            TestMappingsWithRest path = new TestMappingsWithRest();
            return path.testPut();
        } catch (RuntimeException caught) {
            System.out.printf("Caught exception");
        }
        return null;
    }

    @Trace(dispatcher = true)
    public static String deleteMappingWithRest() {
        try {
            TestMappingsWithRest path = new TestMappingsWithRest();
            return path.testDelete();
        } catch (RuntimeException caught) {
            System.out.printf("Caught exception");
        }
        return null;
    }
}
