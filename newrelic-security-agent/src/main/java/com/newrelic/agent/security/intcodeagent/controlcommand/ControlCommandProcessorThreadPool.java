package com.newrelic.agent.security.intcodeagent.controlcommand;

import com.newrelic.agent.security.intcodeagent.filelogging.FileLoggerThreadPool;
import com.newrelic.agent.security.intcodeagent.filelogging.LogLevel;
import com.newrelic.agent.security.intcodeagent.logging.IAgentConstants;

import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

public class ControlCommandProcessorThreadPool {

    public static final String UNEXPECTED_ERROR_WHILE_PROCESSING_CONTROL_COMMAND = "Unexpected error while processing control command";
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

    /**
     * A handler for rejected tasks that throws a
     * {@code RejectedExecutionException}.
     */
    public static class EventAbortPolicy implements RejectedExecutionHandler {

        public static final String CUSTOM_CODE_VULNERABILITY_TASK_REJECTED_FROM_S_S = "Custom Code Vulnerability Task rejected from %s, %s ";

        /**
         * Creates an {@code EventAbortPolicy}.
         */
        public EventAbortPolicy() {
        }

        /**
         * Always throws RejectedExecutionException.
         *
         * @param r the runnable task requested to be executed
         * @param e the executor attempting to execute this task
         * @throws RejectedExecutionException always
         */
        public void rejectedExecution(Runnable r, ThreadPoolExecutor e) {
            logger.log(LogLevel.WARNING, String.format(CUSTOM_CODE_VULNERABILITY_TASK_REJECTED_FROM_S_S, r.toString(), e.toString()),
                    ControlCommandProcessorThreadPool.class.getName());
        }
    }


    private ControlCommandProcessorThreadPool() {
        LinkedBlockingQueue<Runnable> processQueue;
        // load the settings
        processQueue = new LinkedBlockingQueue<>(queueSize);
        executor = new ThreadPoolExecutor(corePoolSize, maxPoolSize, keepAliveTime, timeUnit, processQueue,
                new EventAbortPolicy()) {

            @Override
            protected void afterExecute(Runnable r, Throwable t) {
                if (r instanceof Future<?>) {
                    try {
                        Future<?> future = (Future<?>) r;
                        if (future.isDone()) {
                            future.get();
                        }
                    } catch (Throwable e) {
                        logger.postLogMessageIfNecessary(LogLevel.WARNING, UNEXPECTED_ERROR_WHILE_PROCESSING_CONTROL_COMMAND, e,
                                this.getClass().getName());
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
                        IAgentConstants.K2_LISTERNER + threadNumber.getAndIncrement());
                t.setDaemon(true);
                return t;
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

    public static void shutDownPool() {
        if (instance != null) {
            instance.shutDownThreadPoolExecutor();
        }
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
