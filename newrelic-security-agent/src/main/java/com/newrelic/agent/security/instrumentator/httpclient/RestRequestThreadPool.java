package com.newrelic.agent.security.instrumentator.httpclient;

import com.newrelic.agent.security.intcodeagent.executor.CustomFutureTask;
import com.newrelic.agent.security.intcodeagent.executor.CustomThreadPoolExecutor;
import com.newrelic.agent.security.intcodeagent.filelogging.FileLoggerThreadPool;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import org.apache.commons.lang3.StringUtils;

import java.io.InterruptedIOException;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

public class RestRequestThreadPool {

    /**
     * Thread pool executor.
     */
    protected ThreadPoolExecutor executor;
    private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

    private final int queueSize = 1000;
    private final int maxPoolSize = 5;
    private final int corePoolSize = 3;
    private final long keepAliveTime = 10;
    private final TimeUnit timeUnit = TimeUnit.SECONDS;
    private final boolean allowCoreThreadTimeOut = false;

    private static final AtomicBoolean isWaiting = new AtomicBoolean(false);

    private final Set<String> rejectedIds = ConcurrentHashMap.newKeySet();

    private Set<String> completedReplay = ConcurrentHashMap.newKeySet();

    private Set<String> errorInReplay = ConcurrentHashMap.newKeySet();

    private Set<String> clearFromPending = ConcurrentHashMap.newKeySet();

    /**
     * "generatedEvents":
     *     {
     *         "ORIGIN_APPUUID_1" : {"FUZZ_ID_1":["EVENT_ID_1"], "FUZZ_ID_2":["EVENT_ID_2"]},
     *     }
     * */
    private final Map<String, Map<String, Set<String>>> generatedEvents = new ConcurrentHashMap();


    public void resetIASTProcessing() {
        getAllControlCommandID(generatedEvents);
        generatedEvents.clear();
        completedReplay.clear();
        clearFromPending.clear();
        errorInReplay.clear();
        executor.getQueue().clear();
    }

    private void getAllControlCommandID(Map<String, Map<String, Set<String>>> generatedEvents) {
        if(generatedEvents == null || generatedEvents.isEmpty()) {
            return;
        }

        for (Map<String, Set<String>> applicationMap : generatedEvents.values()) {
            rejectedIds.addAll(applicationMap.keySet());
        }
    }

    private RestRequestThreadPool() {
        LinkedBlockingQueue<Runnable> processQueue;
        // load the settings
        processQueue = new LinkedBlockingQueue<>(queueSize);
        executor = new CustomThreadPoolExecutor(corePoolSize, maxPoolSize, keepAliveTime, timeUnit, processQueue, new EventAbortPolicy()) {

            @Override
            protected void afterExecute(Runnable r, Throwable t) {
                try {
                    super.afterExecute(r, t);
                    String controlCommandId = null;
                    if (r instanceof CustomFutureTask<?> && ((CustomFutureTask<?>) r).getTask() instanceof RestRequestProcessor) {
                        RestRequestProcessor task = (RestRequestProcessor) ((CustomFutureTask<?>) r).getTask();
                        controlCommandId = task.getControlCommand().getId();
                        if(task.isSuccessful()){
                            completedReplay.add(controlCommandId);
                        } else if (task.isExceptionRaised() && task.getError() instanceof InterruptedIOException) {
                            clearFromPending.add(controlCommandId);
                        } else if(task.isExceptionRaised()) {
                            errorInReplay.add(controlCommandId);
                        } else {
                            clearFromPending.add(controlCommandId);
                        }
                        if (StringUtils.isBlank(controlCommandId)) {
                            rejectedIds.add(controlCommandId);
                        }
                    }
                } catch (Exception ignored) {
                }
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

    private static final class InstanceHolder {
        static final RestRequestThreadPool instance = new RestRequestThreadPool();
    }
    public static RestRequestThreadPool getInstance() {
        return InstanceHolder.instance;
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

    public Set<String> getRejectedIds() {
        return rejectedIds;
    }

    public Set<String> getCompletedReplay() {
        return completedReplay;
    }

    public Set<String> getErrorInReplay() {
        return errorInReplay;
    }

    public Set<String> getClearFromPending() {
        return clearFromPending;
    }

    public void registerEventForProcessedCC(String controlCommandId, String eventId, String originAppUuid) {
        if(StringUtils.isAnyBlank(controlCommandId, eventId)){
            return;
        }
        if(!generatedEvents.containsKey(originAppUuid)){
            logger.log(LogLevel.FINE, String.format("Entry from map of generatedEvents for %s is missing. generatedEvents are : %s", originAppUuid, generatedEvents), RestRequestThreadPool.class.getName());
        }

        if(generatedEvents.get(originAppUuid).containsKey(controlCommandId)) {
            generatedEvents.get(originAppUuid).get(controlCommandId).add(eventId);
        } else {
            System.out.println("controlCommandId is not present for : "+controlCommandId);
        }
    }

    public Map<String, Map<String, Set<String>>> getGeneratedEvents() {
        return generatedEvents;
    }
}
