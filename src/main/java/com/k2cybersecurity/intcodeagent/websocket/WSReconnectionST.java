package com.k2cybersecurity.intcodeagent.websocket;

import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import com.k2cybersecurity.intcodeagent.filelogging.LogLevel;

import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.WSRECONNECTSCHEDULEDTHREAD_;

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
                logger.log(LogLevel.ERROR, ERROR_WHILE_WS_RECONNECTION + e.getMessage() + COLON_SEPARATOR + e.getCause(), WSClient.class.getName());
                logger.log(LogLevel.DEBUG, ERROR_WHILE_WS_RECONNECTION, e, WSClient.class.getName());
                logger.postLogMessageIfNecessary(LogLevel.ERROR, ERROR_WHILE_WS_RECONNECTION + e.getMessage() + COLON_SEPARATOR + e.getCause(), e, WSClient.class.getName());
            } finally {
                if (!WSClient.isConnected()) {
                    futureTask = scheduledService.schedule(runnable, 30, TimeUnit.SECONDS);
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
                        WSRECONNECTSCHEDULEDTHREAD_ + threadNumber.getAndIncrement());
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
            logger.log(LogLevel.WARN, "Error while starting: ", e, WSReconnectionST.class.getName());
        }
        throw null;
    }

    public void submitNewTaskSchedule() {
        synchronized (lock) {
            if (futureTask == null || futureTask.isDone()) {
                if (scheduledService.isShutdown()) {
                    instance.instantiateScheduler();
                }
                futureTask = scheduledService.schedule(runnable, 30, TimeUnit.SECONDS);
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
                        logger.log(LogLevel.FATAL, "Thread pool executor did not terminate",
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
