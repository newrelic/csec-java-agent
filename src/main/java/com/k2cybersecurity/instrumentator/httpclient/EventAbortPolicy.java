package com.k2cybersecurity.instrumentator.httpclient;

import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import com.k2cybersecurity.intcodeagent.filelogging.LogLevel;

import java.util.concurrent.RejectedExecutionHandler;
import java.util.concurrent.ThreadPoolExecutor;

public class EventAbortPolicy implements RejectedExecutionHandler {
    private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();


    public EventAbortPolicy() {
    }

    public void rejectedExecution(Runnable r, ThreadPoolExecutor e) {
        logger.log(LogLevel.WARNING, "Fuzz request " + r.toString() + " rejected from  " + e.toString(), EventAbortPolicy.class.getName());
    }
}