package com.newrelic.agent.security.instrumentator.httpclient;

import com.newrelic.agent.security.intcodeagent.filelogging.FileLoggerThreadPool;
import com.newrelic.api.agent.security.utils.logging.LogLevel;

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