package com.newrelic.agent.security.instrumentator.httpclient;

import com.newrelic.agent.security.intcodeagent.executor.CustomFutureTask;
import com.newrelic.agent.security.intcodeagent.executor.CustomThreadPoolExecutor;
import com.newrelic.agent.security.intcodeagent.filelogging.FileLoggerThreadPool;
import com.newrelic.agent.security.intcodeagent.filelogging.LogLevel;
import org.apache.commons.lang3.StringUtils;

import java.util.Set;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

public class RestRequestThreadPool {

    /**
     * Thread pool executor.
     */
    protected ThreadPoolExecutor executor;
    private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();


    private static RestRequestThreadPool instance;

    private final int queueSize = 1000;
    private final int maxPoolSize = 5;
    private final int corePoolSize = 3;
    private final long keepAliveTime = 10;
    private final TimeUnit timeUnit = TimeUnit.SECONDS;
    private final boolean allowCoreThreadTimeOut = false;
    private static final Object mutex = new Object();

    private static final AtomicBoolean isWaiting = new AtomicBoolean(false);

    private Set<String> processedIds = ConcurrentHashMap.newKeySet();

    private RestRequestThreadPool() {
        LinkedBlockingQueue<Runnable> processQueue;
        // load the settings
        processQueue = new LinkedBlockingQueue<>(queueSize);
        executor = new CustomThreadPoolExecutor(corePoolSize, maxPoolSize, keepAliveTime, timeUnit, processQueue, new EventAbortPolicy()) {

            @Override
            protected void afterExecute(Runnable r, Throwable t) {
                if (r instanceof CustomFutureTask<?> && ((CustomFutureTask<?>) r).getTask() instanceof RestRequestProcessor) {
                    RestRequestProcessor task = (RestRequestProcessor) ((CustomFutureTask<?>) r).getTask();
                    if(StringUtils.isNotBlank(task.getControlCommand().getId())){
                        processedIds.add(task.getControlCommand().getId());
                    }
                }
                super.afterExecute(r, t);
            }

            @Override
            protected void beforeExecute(Thread t, Runnable r) {
                super.beforeExecute(t, r);
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

    public static RestRequestThreadPool getInstance() {

        if (instance == null) {
            synchronized (mutex) {
                if (instance == null) {
                    instance = new RestRequestThreadPool();
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
                        logger.log(LogLevel.SEVERE, "Thread pool executor did not terminate",
                                RestRequestThreadPool.class.getName());
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

    public Set<String> getProcessedIds() {
        return processedIds;
    }

}
