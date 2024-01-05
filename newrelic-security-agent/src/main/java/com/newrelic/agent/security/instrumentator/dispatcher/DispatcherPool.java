package com.newrelic.agent.security.instrumentator.dispatcher;

import com.newrelic.agent.security.AgentInfo;
import com.newrelic.agent.security.instrumentator.httpclient.RestRequestThreadPool;
import com.newrelic.agent.security.intcodeagent.executor.CustomFutureTask;
import com.newrelic.agent.security.intcodeagent.executor.CustomThreadPoolExecutor;
import com.newrelic.agent.security.intcodeagent.filelogging.FileLoggerThreadPool;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import com.newrelic.agent.security.intcodeagent.logging.IAgentConstants;
import com.newrelic.agent.security.intcodeagent.models.javaagent.EventStats;
import com.newrelic.agent.security.intcodeagent.models.javaagent.ExitEventBean;
import com.newrelic.api.agent.NewRelic;
import com.newrelic.api.agent.TraceMetadata;
import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.agent.security.util.AgentUsageMetric;
import com.newrelic.agent.security.util.IUtilConstants;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.SecurityMetaData;
import org.apache.commons.lang3.StringUtils;

import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

import static com.newrelic.agent.security.intcodeagent.logging.IAgentConstants.NR_APM_SPAN_ID;
import static com.newrelic.agent.security.intcodeagent.logging.IAgentConstants.NR_APM_TRACE_ID;

public class DispatcherPool {

    /**
     * Thread pool executor.
     */
    private ThreadPoolExecutor executor;
    private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

    final int queueSize = 300;
    final int maxPoolSize = 7;
    final int corePoolSize = 4;
    final long keepAliveTime = 10;
    final TimeUnit timeUnit = TimeUnit.SECONDS;
    final boolean allowCoreThreadTimeOut = false;

    private Set<String> eid;

    public ThreadPoolExecutor getExecutor() {
        return executor;
    }

    public int getMaxQueueSize() {
        return queueSize;
    }


    /**
     * A handler for rejected tasks that throws a
     * {@code RejectedExecutionException}.
     */
    public static class EventAbortPolicy implements RejectedExecutionHandler {
        /**
         * Creates an {@code ValidationAbortPolicy}.
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
            if (r instanceof CustomFutureTask<?> && ((CustomFutureTask<?>) r).getTask() instanceof Dispatcher) {
                Dispatcher dispatcher = (Dispatcher) ((CustomFutureTask<?>) r).getTask();
                if(dispatcher.getSecurityMetaData()!= null && dispatcher.getSecurityMetaData().getFuzzRequestIdentifier().getK2Request()){
                    String fuzzRequestId = dispatcher.getSecurityMetaData().getCustomAttribute(GenericHelper.CSEC_PARENT_ID, String.class);
                    RestRequestThreadPool.getInstance().getRejectedIds().add(fuzzRequestId);
                }

                if(dispatcher.getSecurityMetaData() != null) {
                    if(dispatcher.getSecurityMetaData().getFuzzRequestIdentifier().getK2Request()){
                        AgentInfo.getInstance().getJaHealthCheck().getIastEventStats().incrementRejectedCount();
                    } else {
                        AgentInfo.getInstance().getJaHealthCheck().getRaspEventStats().incrementRejectedCount();
                    }
                } else if (dispatcher.getExitEventBean() != null) {
                    AgentInfo.getInstance().getJaHealthCheck().getExitEventStats().incrementRejectedCount();
                }
            }
            AgentInfo.getInstance().getJaHealthCheck().incrementDropCount();
            AgentInfo.getInstance().getJaHealthCheck().incrementEventRejectionCount();
			logger.log(LogLevel.FINEST,"Event Dispatch Task " + r.toString() + " rejected from  " + e.toString(), DispatcherPool.class.getName());
        }
    }

    private DispatcherPool() {
        LinkedBlockingQueue<Runnable> processQueue;
        // load the settings
        processQueue = new LinkedBlockingQueue<>(queueSize);
        eid = ConcurrentHashMap.newKeySet();
        executor = new CustomThreadPoolExecutor(corePoolSize, maxPoolSize, keepAliveTime, timeUnit, processQueue,
                new EventAbortPolicy()) {

            @Override
            protected void afterExecute(Runnable r, Throwable t) {
                try {
                    if( t != null) {
                        AgentInfo.getInstance().getJaHealthCheck().incrementDropCount();
                        AgentInfo.getInstance().getJaHealthCheck().incrementEventProcessingErrorCount();
                        incrementCount(r, IUtilConstants.ERROR);
                    } else {
                        AgentInfo.getInstance().getJaHealthCheck().incrementProcessedCount();
                        incrementCount(r, IUtilConstants.PROCESSED);
                    }
                } catch (Throwable ignored) {
                    logger.log(LogLevel.FINEST, "Error while Dispatcher matric processing", ignored, DispatcherPool.class.getName());
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
                        IAgentConstants.K2_JAVA_AGENT + threadNumber.getAndIncrement());
                t.setDaemon(true);
                return t;
            }
        });
    }

    private void incrementCount(Runnable r, String type) {
        EventStats eventStats = null;
        if (r instanceof CustomFutureTask<?> && ((CustomFutureTask<?>) r).getTask() instanceof Dispatcher) {
            Dispatcher dispatcher = (Dispatcher) ((CustomFutureTask<?>) r).getTask();
            if(dispatcher.getSecurityMetaData() != null) {
                if(dispatcher.getSecurityMetaData().getFuzzRequestIdentifier().getK2Request()){
                    eventStats = AgentInfo.getInstance().getJaHealthCheck().getIastEventStats();
                } else {
                    eventStats = AgentInfo.getInstance().getJaHealthCheck().getRaspEventStats();
                }
            } else if (dispatcher.getExitEventBean() != null) {
                eventStats = AgentInfo.getInstance().getJaHealthCheck().getExitEventStats();
            }
        }
        if(eventStats == null){
            return;
        }
        switch (type){
            case IUtilConstants.ERROR:
                eventStats.incrementErrorCount();
                break;
            case IUtilConstants.PROCESSED:
                eventStats.incrementProcessedCount();
                break;
            case IUtilConstants.SENT:
                eventStats.incrementSentCount();
                break;
            case IUtilConstants.REJECTED:
                eventStats.incrementRejectedCount();
                break;
            default:
                logger.log(LogLevel.FINEST, String.format("Couldn't update event matric for task :%s and type : %s", r, type), DispatcherPool.class.getName());
        }
    }

    private static final class InstanceHolder {
        static final DispatcherPool instance = new DispatcherPool();
    }
    public static DispatcherPool getInstance() {
        return InstanceHolder.instance;
    }

    public Set<String> getEid() {
        return eid;
    }


    public void dispatchEvent(AbstractOperation operation, SecurityMetaData securityMetaData) {
        AgentInfo.getInstance().getJaHealthCheck().incrementInvokedHookCount();

        if (executor.isShutdown()) {
            return;
        }

        if(!securityMetaData.getFuzzRequestIdentifier().getK2Request() && !AgentUsageMetric.isRASPProcessingActive()){
            AgentInfo.getInstance().getJaHealthCheck().getRaspEventStats().incrementRejectedCount();
            AgentInfo.getInstance().getJaHealthCheck().incrementEventRejectionCount();
            return;
        }

        if (!operation.isEmpty() && securityMetaData.getFuzzRequestIdentifier().getK2Request()) {
            if (StringUtils.equals(securityMetaData.getFuzzRequestIdentifier().getApiRecordId(), operation.getApiID()) && StringUtils.equals(securityMetaData.getFuzzRequestIdentifier().getNextStage().getStatus(), IAgentConstants.VULNERABLE)) {
                eid.add(operation.getExecutionId());
            }
        }
        // Register in Processed CC map
        if(securityMetaData.getFuzzRequestIdentifier().getK2Request()) {
            String parentId = securityMetaData.getCustomAttribute(
                    GenericHelper.CSEC_PARENT_ID, String.class);
            if (StringUtils.isNotBlank(parentId)) {
                RestRequestThreadPool.getInstance().getProcessedIds().putIfAbsent(parentId, new HashSet<>());
            }
            if (StringUtils.equals(securityMetaData.getFuzzRequestIdentifier().getApiRecordId(), operation.getApiID())) {
                RestRequestThreadPool.getInstance()
                        .registerEventForProcessedCC(parentId, operation.getExecutionId());
            }
        }

        // Update NR Trace info
        TraceMetadata traceMetadata = NewRelic.getAgent().getTraceMetadata();
        securityMetaData.addCustomAttribute(NR_APM_TRACE_ID, traceMetadata.getTraceId());
        securityMetaData.addCustomAttribute(NR_APM_SPAN_ID, traceMetadata.getSpanId());
        this.executor.submit(new Dispatcher(operation, new SecurityMetaData(securityMetaData)));
    }

    public void dispatchExitEvent(ExitEventBean exitEventBean) {
        if (executor.isShutdown()) {
            return;
        }

        // Update NR Trace info
        SecurityMetaData securityMetaData = NewRelicSecurity.getAgent().getSecurityMetaData();
        TraceMetadata traceMetadata = NewRelic.getAgent().getTraceMetadata();
        securityMetaData.addCustomAttribute(NR_APM_TRACE_ID, traceMetadata.getTraceId());
        securityMetaData.addCustomAttribute(NR_APM_SPAN_ID, traceMetadata.getSpanId());
        this.executor.submit(new Dispatcher(exitEventBean));
    }

    public static void shutDownPool() {
        InstanceHolder.instance.shutDownThreadPoolExecutor();
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
                                DispatcherPool.class.getName());
                    }
                }
            } catch (InterruptedException e) {
            }
        }

    }

    public void reset() {
        executor.getQueue().clear();
    }
}
