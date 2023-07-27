package com.newrelic.agent.security.intcodeagent.websocket;

import com.newrelic.agent.security.intcodeagent.filelogging.FileLoggerThreadPool;
import com.newrelic.agent.security.intcodeagent.filelogging.LogLevel;
import com.newrelic.agent.security.intcodeagent.logging.IAgentConstants;
import com.newrelic.agent.security.intcodeagent.utils.CommonUtils;

import java.security.SecureRandom;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

public class WSReconnectionST {
    public static final String ERROR_WHILE_WS_RECONNECTION = "Error while WS reconnection : ";
    public static final String COLON_SEPARATOR = " : ";
    private static WSReconnectionST instance;

    private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

    private static ScheduledExecutorService scheduledService;

    private static final Object lock = new Object();

    private ScheduledFuture futureTask;

    private Runnable runnable = new Runnable() {
        @Override
        public void run() {
            try {
                WSClient.reconnectWSClient();
            } catch (Exception e) {
                logger.log(LogLevel.SEVERE, ERROR_WHILE_WS_RECONNECTION + e.getMessage() + COLON_SEPARATOR + e.getCause(), WSClient.class.getName());
                logger.log(LogLevel.FINER, ERROR_WHILE_WS_RECONNECTION, e, WSClient.class.getName());
                logger.postLogMessageIfNecessary(LogLevel.SEVERE, ERROR_WHILE_WS_RECONNECTION + e.getMessage() + COLON_SEPARATOR + e.getCause(), e, WSClient.class.getName());
            } finally {
                if (!WSUtils.isConnected()) {
                    int delay = CommonUtils.generateSecureRandomBetween(5, 15);
                    logger.log(LogLevel.INFO, String.format(WSUtils.NEXT_WS_CONNECTION_ATTEMPT_WILL_BE_IN_S_SECONDS, delay), WSReconnectionST.class.getName());
                    futureTask = scheduledService.schedule(runnable, delay, TimeUnit.SECONDS);
                }
            }
        }
    };

    private void instantiateScheduler() {
        scheduledService = Executors.newSingleThreadScheduledExecutor(new ThreadFactory() {
            private final AtomicInteger threadNumber = new AtomicInteger(1);

            @Override
            public Thread newThread(Runnable r) {
                return new Thread(Thread.currentThread().getThreadGroup(), r,
                        IAgentConstants.WSRECONNECTSCHEDULEDTHREAD_ + threadNumber.getAndIncrement());
            }
        });
    }

    private WSReconnectionST() {
        instantiateScheduler();
    }


    public static WSReconnectionST getInstance() {
        try {
            if (instance == null) {
                synchronized (lock) {
                    if (instance == null) {
                        instance = new WSReconnectionST();
                    }
                }
            }
            return instance;
        } catch (Throwable e) {
            logger.log(LogLevel.WARNING, "Error while starting: ", e, WSReconnectionST.class.getName());
        }
        throw null;
    }

    public void submitNewTaskSchedule(int delay) {
        synchronized (lock) {
            if (futureTask == null || futureTask.isDone()) {
                if (scheduledService.isShutdown()) {
                    instance.instantiateScheduler();
                }
                futureTask = scheduledService.schedule(runnable, delay, TimeUnit.SECONDS);
            }
        }
    }

    public static void cancelTask(boolean force) {
        if (instance != null) {
            if (instance.futureTask == null) {
                return;
            }
            if (instance.futureTask != null && (force || instance.futureTask.isDone())) {
                instance.futureTask.cancel(force);
            }
        }
    }

    public static void shutDownPool() {
        if (instance != null) {
            instance.shutDownThreadPoolExecutor();
        }
        instance = null;
    }

    /**
     * Shut down the thread pool executor. Calls normal shutdown of thread pool
     * executor and awaits for termination. If not terminated, forcefully shuts down
     * the executor after a timeout.
     */
    public void shutDownThreadPoolExecutor() {

        if (scheduledService != null) {
            try {
                scheduledService.shutdown(); // disable new tasks from being submitted
                if (!scheduledService.awaitTermination(10, TimeUnit.SECONDS)) {
                    // wait for termination for a timeout
                    scheduledService.shutdownNow(); // cancel currently executing tasks

                    if (!scheduledService.awaitTermination(10, TimeUnit.SECONDS)) {
                        logger.log(LogLevel.SEVERE, "Thread pool executor did not terminate",
                                WSReconnectionST.class.getName());
                    } else {
                        logger.log(LogLevel.INFO, "Thread pool executor terminated",
                                WSReconnectionST.class.getName());
                    }
                }
            } catch (InterruptedException e) {
            }
        }
    }
}
