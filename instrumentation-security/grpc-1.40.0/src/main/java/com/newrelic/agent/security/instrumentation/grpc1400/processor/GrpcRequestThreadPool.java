package com.newrelic.agent.security.instrumentation.grpc1400.processor;

import com.newrelic.api.agent.security.instrumentation.helpers.GrpcClientRequestReplayHelper;
import com.newrelic.api.agent.security.schema.StringUtils;

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
                try {
                    super.afterExecute(r, t);
                    GrpcClientRequestReplayHelper.getInstance().setInProcessRequestQueue(getQueue());
                    String controlCommandId = null;
                    System.out.println("1 After execute : "+(r instanceof CustomFutureTask<?> && ((CustomFutureTask<?>) r).getTask() instanceof GrpcRequestProcessor));
                    System.out.println("2 After execute : "+((CustomFutureTask<?>) r).get());
                    if (r instanceof CustomFutureTask<?> && ((CustomFutureTask<?>) r).getTask() instanceof GrpcRequestProcessor) {
                        Object result = (Object) ((CustomFutureTask<?>) r).get();
                        GrpcRequestProcessor task = (GrpcRequestProcessor) ((CustomFutureTask<?>) r).getTask();
                        controlCommandId = task.getPartialControlCommand().getId();
                        System.out.println("control command id : " + controlCommandId);
                        if (t != null || result != null) {
                            if (StringUtils.isNotBlank(controlCommandId)) {
                                GrpcClientRequestReplayHelper.getInstance().getRejectedIds().add(controlCommandId);
                            }
                        } else {
                            GrpcClientRequestReplayHelper.getInstance().getProcessedIds().putIfAbsent(controlCommandId, new HashSet<>());
                        }
                    }
                    System.out.println("3 After execute");
                    if (StringUtils.isNotBlank(controlCommandId)) {
                        GrpcClientRequestReplayHelper.getInstance().getPendingIds().remove(controlCommandId);
                    }
                } catch (InterruptedException | ExecutionException e) {
                    System.out.print("my error :: ");
                    e.printStackTrace();
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
                        System.out.println("Thread pool executor did not terminate");
                    }
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