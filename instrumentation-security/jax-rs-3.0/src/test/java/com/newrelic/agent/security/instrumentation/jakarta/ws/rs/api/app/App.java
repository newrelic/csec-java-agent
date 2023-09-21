package com.newrelic.agent.security.instrumentation.jakarta.ws.rs.api.app;

import com.newrelic.api.agent.Trace;


public class App {
    @Trace(dispatcher = true)
    public static String callPut() {
        TestMapping path=new TestMapping();
        return path.putIt();
    }

    @Trace(dispatcher = true)
    public static String callPost() {
        TestMapping path=new TestMapping();
        return path.postIt();
    }

    @Trace(dispatcher = true)
    public static String callGet() {
        TestMapping path=new TestMapping();
        return path.getIt();
    }

    @Trace(dispatcher = true)
    public static String callDelete() {
        TestMapping path=new TestMapping();
        return path.deleteIt();
    }

    @Trace(dispatcher = true)
    public static String callHead() {
        TestMapping path=new TestMapping();
        return path.headIt();
    }

    @Trace(dispatcher = true)
    public static String callOption() {
        TestMapping path=new TestMapping();
        return path.optionsIt();
    }
    @Trace(dispatcher = true)
    public static String callPatch() {
        TestMapping path=new TestMapping();
        return path.patchIt();
    }

    @Trace(dispatcher = true)
    public static String callPath() {
        TestMapping path=new TestMapping();
        return path.pathIt();
    }
}
