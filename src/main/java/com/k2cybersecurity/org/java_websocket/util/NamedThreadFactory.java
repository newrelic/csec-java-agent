package com.k2cybersecurity.org.java_websocket.util;

import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicInteger;

public class NamedThreadFactory implements ThreadFactory {
    private final ThreadFactory defaultThreadFactory = Executors.defaultThreadFactory();
    private final AtomicInteger threadNumber = new AtomicInteger(1);
    private final String threadPrefix;

    public NamedThreadFactory(String threadPrefix) {
        this.threadPrefix = threadPrefix;
    }

    @Override
    public Thread newThread(Runnable runnable) {
        String hello = "k2";
        Thread thread = defaultThreadFactory.newThread(runnable);
        thread.setName(hello + threadPrefix + "-" + threadNumber);
        thread.setDaemon(true);
        return thread;
    }
}