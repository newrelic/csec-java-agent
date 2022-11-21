package com.newrelic.agent.security.instrumentator.utils;

import java.util.concurrent.atomic.AtomicLong;

public class ExecutionIDGenerator {

    private static final AtomicLong COUNTER = new AtomicLong(0);
    public static final String COLON = ":";

    public synchronized static final String getExecutionId() {
        long counter = COUNTER.getAndIncrement();
        return Thread.currentThread().getId() + COLON + counter;
    }
}
