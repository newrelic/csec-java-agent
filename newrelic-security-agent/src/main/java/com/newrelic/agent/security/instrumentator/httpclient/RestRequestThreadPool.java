package com.newrelic.agent.security.instrumentator.httpclient;

import com.newrelic.agent.security.intcodeagent.executor.CustomFutureTask;
import com.newrelic.agent.security.intcodeagent.executor.CustomThreadPoolExecutor;
import com.newrelic.agent.security.intcodeagent.filelogging.FileLoggerThreadPool;
import com.newrelic.agent.security.intcodeagent.filelogging.LogLevel;
import org.apache.commons.lang3.StringUtils;

import java.util.Collections;
import java.util.Map;
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

    private final Map<String, Set<String>> processedIds = new ConcurrentHashMap();

    private final Map<String, Set<String>> currentProcessingIds = new ConcurrentHashMap();

    private final Set<String> pendingIds = ConcurrentHashMap.newKeySet();

    private RestRequestThreadPool() {
        LinkedBlockingQueue<Runnable> processQueue;
        // load the settings
        processQueue = new LinkedBlockingQueue<>(queueSize);
        executor = new CustomThreadPoolExecutor(corePoolSize, maxPoolSize, keepAliveTime, timeUnit, processQueue, new EventAbortPolicy()) {

            @Override
            protected void afterExecute(Runnable r, Throwable t) {
                if (r instanceof CustomFutureTask<?> && ((CustomFutureTask<?>) r).getTask() instanceof RestRequestProcessor) {
                    RestRequestProcessor task = (RestRequestProcessor) ((CustomFutureTask<?>) r).getTask();
                    String controlCommandId = task.getControlCommand().getId();
                    if(StringUtils.isNotBlank(controlCommandId)){
                        if(!currentProcessingIds.containsKey(controlCommandId)) {
                            processedIds.put(controlCommandId, Collections.emptySet());
                        } else {
                            processedIds.put(controlCommandId, currentProcessingIds.get(controlCommandId));
                        }
                        pendingIds.remove(controlCommandId);
                        currentProcessingIds.remove(controlCommandId);
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

    public Map<String, Set<String>> getProcessedIds() {
        return processedIds;
    }

    public Set<String> getPendingIds() {
        return pendingIds;
    }

    public void registerEventForProcessedCC(String controlCommandId, String eventId) {
        if(StringUtils.isAnyBlank(controlCommandId, eventId)){
            return;
        }
        Set<String> registeredEvents;
        if(!currentProcessingIds.containsKey(controlCommandId)){
            currentProcessingIds.putIfAbsent(controlCommandId, ConcurrentHashMap.newKeySet());
        }
        registeredEvents = currentProcessingIds.get(controlCommandId);
        registeredEvents.add(eventId);
    }

    public void removeFromProcessedCC(String controlCommandId) {
        if(StringUtils.isNotBlank(controlCommandId)){
            processedIds.remove(controlCommandId);
        }
    }

}
