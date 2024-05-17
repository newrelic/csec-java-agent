package com.newrelic.agent.security.instrumentation.grpc1220.processor;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GrpcClientRequestReplayHelper;
import com.newrelic.api.agent.security.schema.StringUtils;
import com.newrelic.api.agent.security.utils.logging.LogLevel;

import java.util.HashSet;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.RunnableFuture;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

public class GrpcRequestThreadPool {
    public static final String CALL_FAILED_REQUEST_S_REASON = "Call failed : request %s reason : ";

    /**
     * Thread pool executor.
     */
    protected ThreadPoolExecutor executor;

    private static GrpcRequestThreadPool instance;

    private final int queueSize = 1000;
    private final int maxPoolSize = 5;
    private final int corePoolSize = 3;
    private final long keepAliveTime = 10;
    private final TimeUnit timeUnit = TimeUnit.SECONDS;
    private final boolean allowCoreThreadTimeOut = false;
    private static final Object mutex = new Object();

    private static final AtomicBoolean isWaiting = new AtomicBoolean(false);

    private GrpcRequestThreadPool() {
        LinkedBlockingQueue<Runnable> processQueue;
        // load the settings
        processQueue = new LinkedBlockingQueue<>(queueSize);
        executor = new ThreadPoolExecutor(corePoolSize, maxPoolSize, keepAliveTime, timeUnit, processQueue, new EventAbortPolicy()){
            @Override
            protected void afterExecute(Runnable r, Throwable t) {
                String controlCommandId = null;
                try {
                    super.afterExecute(r, t);
                    GrpcClientRequestReplayHelper.getInstance().setInProcessRequestQueue(getQueue());
                    controlCommandId = null;
                    if (r instanceof CustomFutureTask<?> && ((CustomFutureTask<?>) r).getTask() instanceof GrpcRequestProcessor) {
                        Object result = (Object) ((CustomFutureTask<?>) r).get();
                        GrpcRequestProcessor task = (GrpcRequestProcessor) ((CustomFutureTask<?>) r).getTask();
                        controlCommandId = task.getPartialControlCommand().getId();
                        if (t != null || result != null) {
                            if (StringUtils.isNotBlank(controlCommandId)) {
                                GrpcClientRequestReplayHelper.getInstance().getRejectedIds().add(controlCommandId);
                            }
                        } else {
                            GrpcClientRequestReplayHelper.getInstance().getProcessedIds().putIfAbsent(controlCommandId, new HashSet<>());
                        }
                    }
                    if (StringUtils.isNotBlank(controlCommandId)) {
                        GrpcClientRequestReplayHelper.getInstance().getPendingIds().remove(controlCommandId);
                    }
                } catch (InterruptedException | ExecutionException ignored) {
                }
            }

            @Override
            protected void beforeExecute(Thread t, Runnable r) {
//                GrpcClientRequestReplayHelper.getInstance().setInProcessRequestQueue(getQueue());
                super.beforeExecute(t, r);
            }

            @Override
            protected <T> RunnableFuture<T> newTaskFor(Runnable runnable, T value) {
                return new CustomFutureTask<>(runnable, value);
            }

            @Override
            protected <T> RunnableFuture<T> newTaskFor(Callable<T> callable) {
                return new CustomFutureTask<>(callable);
            }
        };
        executor.allowCoreThreadTimeOut(allowCoreThreadTimeOut);
        executor.setThreadFactory(new ThreadFactory() {
            private final AtomicInteger threadNumber = new AtomicInteger(1);

            @Override
            public Thread newThread(Runnable r) {
                Thread t = new Thread(Thread.currentThread().getThreadGroup(), r,
                        "NewRelic-IAST-RequestRepeater" + threadNumber.getAndIncrement());
                t.setDaemon(true);
                return t;
            }
        });
    }

    public static GrpcRequestThreadPool getInstance() {
        if (instance == null) {
            synchronized (mutex) {
                if (instance == null) {
                    instance = new GrpcRequestThreadPool();
                }
                return instance;
            }
        }
        return instance;
    }


    public void shutDownThreadPoolExecutor() {
        if (executor != null) {
            try {
                executor.shutdown(); // disable new tasks from being submitted
                if (!executor.awaitTermination(1, TimeUnit.SECONDS)) {
                    // wait for termination for a timeout
                    executor.shutdownNow(); // cancel currently executing tasks

                    if (!executor.awaitTermination(1, TimeUnit.SECONDS)) {
                        NewRelicSecurity.getAgent().log(LogLevel.SEVERE, "Thread pool executor did not terminate",
                                GrpcRequestThreadPool.class.getName());                    }
                }
            } catch (InterruptedException e) {
            }
        }
    }

    public int getQueueSize() {
        return this.executor.getQueue().size();
    }

    public BlockingQueue<Runnable> getQueue() {
        return this.executor.getQueue();
    }

    public AtomicBoolean isWaiting() {
        return isWaiting;
    }

    public ThreadPoolExecutor getExecutor() {
        return executor;
    }
}