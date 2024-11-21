package com.nr.agent.security.instrumentation.springweb.springweb.app;

import com.newrelic.api.agent.Trace;

public class App {

    @Trace(dispatcher = true)
    public static String requestMapping() {
        try {
            TestMappings path = new TestMappings();
            return path.testRequest();
        } catch (RuntimeException caught) {
            System.out.print("Caught exception");
        }
        return null;
    }

    @Trace(dispatcher = true)
    public static String getMapping() {
        try {
            TestMappings path = new TestMappings();
            return path.testGet();
        } catch (RuntimeException caught) {
            System.out.print("Caught exception");
        }
        return null;
    }

    @Trace(dispatcher = true)
    public static String postMapping() {
        try {
            TestMappings path = new TestMappings();
            return path.testPost();
        } catch (RuntimeException caught) {
            System.out.print("Caught exception");
        }
        return null;
    }

    @Trace(dispatcher = true)
    public static String patchMapping() {
        try {
            TestMappings path = new TestMappings();
            return path.testPatch();
        } catch (RuntimeException caught) {
            System.out.print("Caught exception");
        }
        return null;
    }

    @Trace(dispatcher = true)
    public static String putMapping() {
        try {
            TestMappings path = new TestMappings();
            return path.testPut();
        } catch (RuntimeException caught) {
            System.out.print("Caught exception");
        }
        return null;
    }

    @Trace(dispatcher = true)
    public static String deleteMapping() {
        try {
            TestMappings path = new TestMappings();
            return path.testDelete();
        } catch (RuntimeException caught) {
            System.out.print("Caught exception");
        }
        return null;
    }

    @Trace(dispatcher = true)
    public static String requestMappingWithRest() {
        try {
            TestMappingsWithRest path = new TestMappingsWithRest();
            return path.testRequest();
        } catch (RuntimeException caught) {
            System.out.print("Caught exception");
        }
        return null;
    }

    @Trace(dispatcher = true)
    public static String getMappingWithRest() {
        try {
            TestMappingsWithRest path = new TestMappingsWithRest();
            return path.testGet();
        } catch (RuntimeException caught) {
            System.out.print("Caught exception");
        }
        return null;
    }

    @Trace(dispatcher = true)
    public static String postMappingWithRest() {
        try {
            TestMappingsWithRest path = new TestMappingsWithRest();
            return path.testPost();
        } catch (RuntimeException caught) {
            System.out.print("Caught exception");
        }
        return null;
    }

    @Trace(dispatcher = true)
    public static String patchMappingWithRest() {
        try {
            TestMappingsWithRest path = new TestMappingsWithRest();
            return path.testPatch();
        } catch (RuntimeException caught) {
            System.out.print("Caught exception");
        }
        return null;
    }

    @Trace(dispatcher = true)
    public static String putMappingWithRest() {
        try {
            TestMappingsWithRest path = new TestMappingsWithRest();
            return path.testPut();
        } catch (RuntimeException caught) {
            System.out.print("Caught exception");
        }
        return null;
    }

    @Trace(dispatcher = true)
    public static String deleteMappingWithRest() {
        try {
            TestMappingsWithRest path = new TestMappingsWithRest();
            return path.testDelete();
        } catch (RuntimeException caught) {
            System.out.print("Caught exception");
        }
        return null;
    }

    @Trace(dispatcher = true)
    public static void batchMappingWithRest() {
        try {
            new TestMappingsWithRest().testBatchMapping();
        } catch (RuntimeException caught) {
            System.out.print("Caught exception");
        }
    }

    @Trace(dispatcher = true)
    public static void mutationWithRest() {
        try {
            new TestMappingsWithRest().testMutation();
        } catch (RuntimeException caught) {
            System.out.print("Caught exception");
        }
    }

    @Trace(dispatcher = true)
    public static void queryWithRest() {
        try {
            new TestMappingsWithRest().testQuery();
        } catch (RuntimeException caught) {
            System.out.print("Caught exception");
        }
    }

    @Trace(dispatcher = true)
    public static void schemaMappingWithRest() {
        try {
            new TestMappingsWithRest().testSchemaMapping();
        } catch (RuntimeException caught) {
            System.out.print("Caught exception");
        }
    }

    @Trace(dispatcher = true)
    public static void subscriptionMappingWithRest() {
        try {
            new TestMappingsWithRest().testSubscriptionMapping();
        } catch (RuntimeException caught) {
            System.out.print("Caught exception");
        }
    }

    @Trace(dispatcher = true)
    public static void batchMapping() {
        try {
            new TestMappings().testBatchMapping();
        } catch (RuntimeException caught) {
            System.out.print("Caught exception");
        }
    }

    @Trace(dispatcher = true)
    public static void mutation() {
        try {
            new TestMappings().testMutation();
        } catch (RuntimeException caught) {
            System.out.print("Caught exception");
        }
    }

    @Trace(dispatcher = true)
    public static void query() {
        try {
            new TestMappings().testQuery();
        } catch (RuntimeException caught) {
            System.out.print("Caught exception");
        }
    }

    @Trace(dispatcher = true)
    public static void schemaMapping() {
        try {
            new TestMappings().testSchemaMapping();
        } catch (RuntimeException caught) {
            System.out.print("Caught exception");
        }
    }

    @Trace(dispatcher = true)
    public static void subscriptionMapping() {
        try {
            new TestMappings().testSubscriptionMapping();
        } catch (RuntimeException caught) {
            System.out.print("Caught exception");
        }
    }
}
