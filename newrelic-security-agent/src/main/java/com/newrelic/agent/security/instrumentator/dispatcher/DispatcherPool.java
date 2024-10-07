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
import com.newrelic.api.agent.security.instrumentation.helpers.GrpcClientRequestReplayHelper;
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
                    if (dispatcher.getSecurityMetaData().getRequest().getIsGrpc()) {
                        GrpcClientRequestReplayHelper.getInstance().getRejectedIds().add(fuzzRequestId);
                    } else {
                        RestRequestThreadPool.getInstance().getRejectedIds().add(fuzzRequestId);
                    }
                }
                AgentInfo.getInstance().getJaHealthCheck().getEventStats().getDispatcher().incrementRejected();
                if(dispatcher.getSecurityMetaData() != null) {
                    if(dispatcher.getSecurityMetaData().getFuzzRequestIdentifier().getK2Request()){
                        AgentInfo.getInstance().getJaHealthCheck().getEventStats().getIastEvents().incrementRejected();
                    }
                    if(dispatcher.getOperation()!= null && dispatcher.getOperation().isLowSeverityHook()) {
                        AgentInfo.getInstance().getJaHealthCheck().getEventStats().getLowSeverityEvents().incrementRejected();
                    }
                } else if (dispatcher.getExitEventBean() != null) {
                    AgentInfo.getInstance().getJaHealthCheck().getEventStats().getExitEvents().incrementRejected();
                }
            }
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
                    if (r instanceof CustomFutureTask<?> && ((CustomFutureTask<?>) r).getTask() instanceof Dispatcher) {
                        Dispatcher dispatcher = (Dispatcher) ((CustomFutureTask<?>) r).getTask();
                        AbstractOperation operation = dispatcher.getOperation();
                        SecurityMetaData securityMetaData = dispatcher.getSecurityMetaData();
                        if(t != null){
                            AgentInfo.getInstance().getJaHealthCheck().getEventStats().getDispatcher().incrementError();
                            if(operation != null) {
                                if(securityMetaData != null && securityMetaData.getFuzzRequestIdentifier().getK2Request()) {
                                    AgentInfo.getInstance().getJaHealthCheck().getEventStats().getIastEvents().incrementError();
                                }
                                if (operation.isLowSeverityHook()) {
                                    AgentInfo.getInstance().getJaHealthCheck().getEventStats().getLowSeverityEvents().incrementError();
                                }
                            } else if (dispatcher.getExitEventBean() != null) {
                                AgentInfo.getInstance().getJaHealthCheck().getEventStats().getExitEvents().incrementError();
                            }
                        } else {
                            AgentInfo.getInstance().getJaHealthCheck().getEventStats().getDispatcher().incrementCompleted();
                            if(operation != null) {
                                if(securityMetaData != null && securityMetaData.getFuzzRequestIdentifier().getK2Request()) {
                                    AgentInfo.getInstance().getJaHealthCheck().getEventStats().getIastEvents().incrementCompleted();
                                }
                                if (operation.isLowSeverityHook()) {
                                    AgentInfo.getInstance().getJaHealthCheck().getEventStats().getLowSeverityEvents().incrementCompleted();
                                }
                            } else if (dispatcher.getExitEventBean() != null) {
                                AgentInfo.getInstance().getJaHealthCheck().getEventStats().getExitEvents().incrementCompleted();
                            }
                        }
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

        if (executor.isShutdown()) {
            AgentInfo.getInstance().getJaHealthCheck().getEventStats().getDroppedDueTo().incrementExecutorUnavailable();
            return;
        }

        if(!securityMetaData.getFuzzRequestIdentifier().getK2Request() && !AgentUsageMetric.isRASPProcessingActive()){
            AgentInfo.getInstance().getJaHealthCheck().getEventStats().getDroppedDueTo().incrementRaspProcessingDeactivated();
            return;
        }

        if (!operation.isEmpty() && securityMetaData.getFuzzRequestIdentifier().getK2Request()) {
            if (StringUtils.equals(securityMetaData.getFuzzRequestIdentifier().getApiRecordId(), operation.getApiID()) && StringUtils.equals(securityMetaData.getFuzzRequestIdentifier().getNextStage().getStatus(), IAgentConstants.VULNERABLE)) {
                eid.add(operation.getExecutionId());
            }
        }
        // Register in Processed CC map
        if (securityMetaData.getFuzzRequestIdentifier().getK2Request()) {
            String parentId = securityMetaData.getCustomAttribute(GenericHelper.CSEC_PARENT_ID, String.class);
            if (StringUtils.isNotBlank(parentId)) {
                if (securityMetaData.getRequest().getIsGrpc()) {
                    GrpcClientRequestReplayHelper.getInstance().getProcessedIds().putIfAbsent(parentId, new HashSet<>());
                    if (StringUtils.equals(securityMetaData.getFuzzRequestIdentifier().getApiRecordId(), operation.getApiID())) {
                        GrpcClientRequestReplayHelper.getInstance().registerEventForProcessedCC(parentId, operation.getExecutionId());
                    }
                } else {
                    RestRequestThreadPool.getInstance().getProcessedIds().putIfAbsent(parentId, new HashSet<>());
                    if (StringUtils.equals(securityMetaData.getFuzzRequestIdentifier().getApiRecordId(), operation.getApiID())) {
                        RestRequestThreadPool.getInstance().registerEventForProcessedCC(parentId, operation.getExecutionId());
                    }
                }
            }
        }

        // Update NR Trace info
        TraceMetadata traceMetadata = NewRelic.getAgent().getTraceMetadata();
        securityMetaData.addCustomAttribute(NR_APM_TRACE_ID, traceMetadata.getTraceId());
        securityMetaData.addCustomAttribute(NR_APM_SPAN_ID, traceMetadata.getSpanId());
        this.executor.submit(new Dispatcher(operation, new SecurityMetaData(securityMetaData)));
        AgentInfo.getInstance().getJaHealthCheck().getEventStats().getDispatcher().incrementSubmitted();

        if(securityMetaData.getFuzzRequestIdentifier().getK2Request()){
            AgentInfo.getInstance().getJaHealthCheck().getEventStats().getIastEvents().incrementSubmitted();
        }
        if(operation.isLowSeverityHook()){
            AgentInfo.getInstance().getJaHealthCheck().getEventStats().getLowSeverityEvents().incrementSubmitted();
        }
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
        AgentInfo.getInstance().getJaHealthCheck().getEventStats().getDispatcher().incrementSubmitted();
        AgentInfo.getInstance().getJaHealthCheck().getEventStats().getExitEvents().incrementSubmitted();
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
        executor.purge();
    }
}
