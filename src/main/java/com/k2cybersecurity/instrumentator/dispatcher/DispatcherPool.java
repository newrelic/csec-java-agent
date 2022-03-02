package com.k2cybersecurity.instrumentator.dispatcher;

import com.k2cybersecurity.instrumentator.K2Instrumentator;
import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import com.k2cybersecurity.intcodeagent.filelogging.LogLevel;
import com.k2cybersecurity.intcodeagent.logging.EventThreadPool.EventAbortPolicy;
import com.k2cybersecurity.intcodeagent.logging.IAgentConstants;
import com.k2cybersecurity.intcodeagent.models.javaagent.*;
import com.k2cybersecurity.intcodeagent.models.operationalbean.AbstractOperationalBean;
import org.apache.commons.lang3.StringUtils;

import java.util.List;
import java.util.Set;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

public class DispatcherPool {

    /**
     * Thread pool executor.
     */
    private ThreadPoolExecutor executor;
    private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();


    private static DispatcherPool instance;

    final int queueSize = 300;
    final int maxPoolSize = 7;
    final int corePoolSize = 4;
    final long keepAliveTime = 10;
    final TimeUnit timeUnit = TimeUnit.SECONDS;
    final boolean allowCoreThreadTimeOut = false;
    private static Object mutex = new Object();

    private Set<String> eid;

    private DispatcherPool() {
        LinkedBlockingQueue<Runnable> processQueue;
        // load the settings
        processQueue = new LinkedBlockingQueue<>(queueSize);
        eid = ConcurrentHashMap.newKeySet();
        executor = new ThreadPoolExecutor(corePoolSize, maxPoolSize, keepAliveTime, timeUnit, processQueue,
                new EventAbortPolicy()) {

            @Override
            protected void afterExecute(Runnable r, Throwable t) {
                if (r instanceof Future<?>) {
                    try {
                        Future<?> future = (Future<?>) r;
                        if (future.isDone()) {
                            K2Instrumentator.JA_HEALTH_CHECK.incrementProcessedCount();
                            future.get();
                        }
                    } catch (Throwable e) {
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
                Thread t = new Thread(Thread.currentThread().getThreadGroup(), r,
                        IAgentConstants.K2_JAVA_AGENT + threadNumber.getAndIncrement());
                t.setDaemon(true);
                return t;
            }
        });
    }

    public static DispatcherPool getInstance() {

        if (instance == null) {
            synchronized (mutex) {
                if (instance == null) {
                    instance = new DispatcherPool();
                }
                return instance;
            }
        }
        return instance;
    }

    public Set<String> getEid() {
        return eid;
    }

    public void dispatchEvent(HttpRequestBean httpRequestBean, AgentMetaData metaData,
                              AbstractOperationalBean event, VulnerabilityCaseType vulnerabilityCaseType) {
        if (executor.isShutdown()) {
            return;
        }
        if (!event.isEmpty() && metaData.isK2FuzzRequest()) {
            if (StringUtils.equals(httpRequestBean.getK2RequestIdentifierInstance().getApiRecordId(), event.getApiID()) && StringUtils.equals(httpRequestBean.getK2RequestIdentifierInstance().getNextStage().getStatus(), IAgentConstants.VULNERABLE)) {
                eid.add(event.getExecutionId());
            }
        }
        this.executor.submit(new Dispatcher(httpRequestBean, metaData, event, vulnerabilityCaseType));
    }

    public void dispatchEvent(HttpRequestBean httpRequestBean, AgentMetaData metaData,
                              List<AbstractOperationalBean> event, VulnerabilityCaseType vulnerabilityCaseType, String currentGenericServletMethodName,
                              Object currentGenericServletInstance,
                              StackTraceElement[] stackTrace, UserClassEntity userClassEntity) {
        if (executor.isShutdown()) {
            return;
        }
        if (!event.isEmpty() && metaData.isK2FuzzRequest()) {
            if (StringUtils.equals(httpRequestBean.getK2RequestIdentifierInstance().getApiRecordId(), event.get(0).getApiID()) && StringUtils.equals(httpRequestBean.getK2RequestIdentifierInstance().getNextStage().getStatus(), IAgentConstants.VULNERABLE)) {
                eid.add(event.get(0).getExecutionId());
            }
        }
        this.executor.submit(new Dispatcher(httpRequestBean, metaData, event, vulnerabilityCaseType, currentGenericServletMethodName,
                currentGenericServletInstance, stackTrace, userClassEntity));
    }

    public void dispatchExitEvent(ExitEventBean exitEventBean) {
        if (executor.isShutdown()) {
            return;
        }
        this.executor.submit(new Dispatcher(exitEventBean));
    }

    /**
     * Specifically for reflected xss
     *
     * @param httpRequestBean
     * @param agentMetaData
     * @param sourceString
     * @param exectionId
     * @param startTime
     * @param reflectedXss
     * @param apiID
     */
    public void dispatchEventRXSS(HttpRequestBean httpRequestBean, AgentMetaData agentMetaData, String sourceString, String exectionId,
                                  long startTime, VulnerabilityCaseType reflectedXss, String currentGenericServletMethodName,
                                  Object currentGenericServletInstance,
                                  StackTraceElement[] stackTrace, UserClassEntity userClassEntity, String apiID) {
        if (executor.isShutdown()) {
            return;
        }
        this.executor.submit(new Dispatcher(httpRequestBean, agentMetaData, reflectedXss, sourceString, exectionId, startTime, currentGenericServletMethodName,
                currentGenericServletInstance, stackTrace, userClassEntity, apiID));
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
                        logger.log(LogLevel.FATAL, "Thread pool executor did not terminate",
                                DispatcherPool.class.getName());
                    }
                }
            } catch (InterruptedException e) {
            }
        }

    }

}
