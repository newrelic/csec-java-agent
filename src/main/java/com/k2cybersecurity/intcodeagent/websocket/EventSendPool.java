package com.k2cybersecurity.intcodeagent.websocket;

import com.k2cybersecurity.instrumentator.K2Instrumentator;
import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import com.k2cybersecurity.intcodeagent.filelogging.LogLevel;
import com.k2cybersecurity.intcodeagent.logging.ServletEventPool.EventAbortPolicy;
import com.k2cybersecurity.intcodeagent.models.javaagent.JavaAgentEventBean;

import java.util.Map;
import java.util.concurrent.*;

public class EventSendPool {

    /**
     * Thread pool executor.
     */
    private ThreadPoolExecutor executor;

    private static EventSendPool instance;

    private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

    public Map<String, Long> getEventMap() {
        return eventMap;
    }

    private Map<String, Long> eventMap = new ConcurrentHashMap<>();

    private EventSendPool() {
        // load the settings
        int queueSize = 1500;
        int maxPoolSize = 1;
        int corePoolSize = 1;
        long keepAliveTime = 60;

        TimeUnit timeUnit = TimeUnit.SECONDS;

        boolean allowCoreThreadTimeOut = false;

        executor = new ThreadPoolExecutor(corePoolSize, maxPoolSize, keepAliveTime, timeUnit,
                new LinkedBlockingQueue<Runnable>(queueSize), new EventAbortPolicy()) {
            @Override
            protected void afterExecute(Runnable r, Throwable t) {
                if (r instanceof Future<?>) {
                    try {
                        Future<?> future = (Future<?>) r;
                        if (future.isDone()) {
                            K2Instrumentator.JA_HEALTH_CHECK.incrementEventSentCount();
                            future.get();
                        }
                    } catch (Throwable e) {
                        K2Instrumentator.JA_HEALTH_CHECK.incrementDropCount();
                    }
                }
                super.afterExecute(r, t);
            }
        };
        executor.allowCoreThreadTimeOut(allowCoreThreadTimeOut);
        executor.setThreadFactory(new ThreadFactory() {
            @Override
            public Thread newThread(Runnable r) {
                Thread t = new Thread(Thread.currentThread().getThreadGroup(), r,
                        "K2-EventSender");
                t.setDaemon(true);
                return t;
            }
        });
    }

    /**
     * @return the instance
     */
    public static EventSendPool getInstance() {
        if (instance == null)
            instance = new EventSendPool();
        return instance;
    }

    public void sendEvent(String event) {
        executor.submit(new EventSender(event));
    }

    public void sendEvent(JavaAgentEventBean event) {
        executor.submit(new EventSender(event));
    }

    public void sendEvent(Object event) {
        executor.submit(new EventSender(event));
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
                                EventSendPool.class.getName());
                    }
                }
            } catch (InterruptedException e) {
            }
        }

    }
}
