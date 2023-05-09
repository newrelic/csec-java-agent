package com.newrelic.agent.security.intcodeagent.executor;

import org.jetbrains.annotations.NotNull;

import java.util.concurrent.*;

public class CustomScheduledThreadPoolExecutor extends ScheduledThreadPoolExecutor {

    public CustomScheduledThreadPoolExecutor(int corePoolSize) {
        super(corePoolSize);
    }

    public CustomScheduledThreadPoolExecutor(int corePoolSize, @NotNull ThreadFactory threadFactory) {
        super(corePoolSize, threadFactory);
    }

    public CustomScheduledThreadPoolExecutor(int corePoolSize, @NotNull RejectedExecutionHandler handler) {
        super(corePoolSize, handler);
    }

    public CustomScheduledThreadPoolExecutor(int corePoolSize, @NotNull ThreadFactory threadFactory, @NotNull RejectedExecutionHandler handler) {
        super(corePoolSize, threadFactory, handler);
    }

    @Override
    protected <T> RunnableFuture<T> newTaskFor(Runnable runnable, T value) {
        return new CustomFutureTask<>(runnable, value);
    }

    @Override
    protected <T> RunnableFuture<T> newTaskFor(Callable<T> callable) {
        return new CustomFutureTask<>(callable);
    }
}