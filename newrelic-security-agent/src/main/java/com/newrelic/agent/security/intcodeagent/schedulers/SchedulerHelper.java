package com.newrelic.agent.security.intcodeagent.schedulers;

import com.newrelic.agent.security.intcodeagent.filelogging.FileLoggerThreadPool;
import com.newrelic.agent.security.intcodeagent.logging.IAgentConstants;

import java.util.Map;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

public class SchedulerHelper {
    private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

    private final ScheduledExecutorService commonExecutor;

    private SchedulerHelper() {
        commonExecutor = Executors.newScheduledThreadPool(1, new ThreadFactory() {
            private final AtomicInteger threadNumber = new AtomicInteger(1);

            @Override
            public Thread newThread(Runnable r) {
                Thread thread = new Thread(Thread.currentThread().getThreadGroup(), r,
                        IAgentConstants.SCHEDULEDTHREAD_ + threadNumber.getAndIncrement());
                thread.setDaemon(true);
                return thread;
            }
        });
    }

    private static final class InstanceHolder {
        static final SchedulerHelper instance = new SchedulerHelper();
    }

    public static SchedulerHelper getInstance() {
        return InstanceHolder.instance;
    }

    private final Map<String, ScheduledFuture<?>> scheduledFutureMap = new ConcurrentHashMap<>();

    public ScheduledFuture<?> scheduleHealthCheck(Runnable command,
                                               long initialDelay,
                                               long period,
                                               TimeUnit unit){
        ScheduledFuture<?> future = commonExecutor.scheduleWithFixedDelay(command, initialDelay, period, unit);
        scheduledFutureMap.put("HC", future);
        return future;
    }

    public ScheduledFuture<?> scheduleLowSeverityFilterCleanup(Runnable command,
                                               long initialDelay,
                                               long period,
                                               TimeUnit unit){
        ScheduledFuture<?> future = commonExecutor.scheduleWithFixedDelay(command, initialDelay, period, unit);
        scheduledFutureMap.put("low-severity-hook-filter-cleanup", future);
        return future;
    }

}
