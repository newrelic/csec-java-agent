package com.newrelic.agent.security.instrumentation.grpc1400.processor;

import java.util.concurrent.RejectedExecutionHandler;
import java.util.concurrent.ThreadPoolExecutor;

public class EventAbortPolicy implements RejectedExecutionHandler {

    public EventAbortPolicy() {
    }

    public void rejectedExecution(Runnable r, ThreadPoolExecutor e) {
        System.out.println("Fuzz request " + r.toString() + " rejected from  " + e.toString());
    }
}