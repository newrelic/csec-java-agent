package com.k2cybersecurity.intcodeagent.controlcommand;

import com.k2cybersecurity.instrumentator.K2Instrumentator;
import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import com.k2cybersecurity.intcodeagent.filelogging.LogLevel;
import com.k2cybersecurity.intcodeagent.logging.EventThreadPool;
import com.k2cybersecurity.intcodeagent.logging.IAgentConstants;

import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

public class ControlCommandProcessorThreadPool {

    /**
     * Thread pool executor.
     */
    protected ThreadPoolExecutor executor;
    private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();


    private static ControlCommandProcessorThreadPool instance;

    private final int queueSize = 1500;
    private final int maxPoolSize = 3;
    private final int corePoolSize = 1;
    private final long keepAliveTime = 10;
    private final TimeUnit timeUnit = TimeUnit.SECONDS;
    private final boolean allowCoreThreadTimeOut = false;
    private static Object mutex = new Object();

    private ControlCommandProcessorThreadPool() {
        LinkedBlockingQueue<Runnable> processQueue;
        // load the settings
        processQueue = new LinkedBlockingQueue<>(queueSize);
        executor = new ThreadPoolExecutor(corePoolSize, maxPoolSize, keepAliveTime, timeUnit, processQueue,
                new EventThreadPool.EventAbortPolicy()) {

            @Override
            protected void afterExecute(Runnable r, Throwable t) {
                if (r instanceof Future<?>) {
                    try {
                        Future<?> future = (Future<?>) r;
                        if (future.isDone()) {
                            K2Instrumentator.JA_HEALTH_CHECK.incrementProcessedCount();
                            future.get();
                        }
                    } catch (Exception e) {
                        K2Instrumentator.JA_HEALTH_CHECK.incrementDropCount();
                    }
                }
                super.afterExecute(r, t);
            }

            @Override
            protected void beforeExecute(Thread t, Runnable r) {
                // TODO increment event proccessed count
                super.beforeExecute(t, r);
            }

        };
        executor.allowCoreThreadTimeOut(allowCoreThreadTimeOut);
        executor.setThreadFactory(new ThreadFactory() {
            private final AtomicInteger threadNumber = new AtomicInteger(1);

            @Override
            public Thread newThread(Runnable r) {
                return new Thread(Thread.currentThread().getThreadGroup(), r,
                        IAgentConstants.K2_JAVA_AGENT + threadNumber.getAndIncrement());
            }
        });
    }

    public static ControlCommandProcessorThreadPool getInstance() {

        if (instance == null) {
            synchronized (mutex) {
                if (instance == null) {
                    instance = new ControlCommandProcessorThreadPool();
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
                                ControlCommandProcessorThreadPool.class.getName());
                    }
                }
            } catch (InterruptedException e) {
            }
        }
    }

}
