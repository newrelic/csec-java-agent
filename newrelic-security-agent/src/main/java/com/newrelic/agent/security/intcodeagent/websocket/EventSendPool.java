package com.newrelic.agent.security.intcodeagent.websocket;

import com.newrelic.agent.security.AgentInfo;
import com.newrelic.agent.security.instrumentator.dispatcher.Dispatcher;
import com.newrelic.agent.security.instrumentator.httpclient.RestRequestThreadPool;
import com.newrelic.agent.security.intcodeagent.executor.CustomFutureTask;
import com.newrelic.agent.security.intcodeagent.executor.CustomThreadPoolExecutor;
import com.newrelic.agent.security.intcodeagent.filelogging.FileLoggerThreadPool;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import com.newrelic.agent.security.intcodeagent.models.javaagent.EventStats;
import com.newrelic.agent.security.intcodeagent.models.javaagent.ExitEventBean;
import com.newrelic.agent.security.intcodeagent.models.javaagent.JavaAgentEventBean;
import com.newrelic.agent.security.util.AgentUsageMetric;
import com.newrelic.agent.security.util.IUtilConstants;
import com.newrelic.api.agent.security.instrumentation.helpers.GrpcClientRequestReplayHelper;

import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;

public class EventSendPool {

    public static final int QUEUE_SIZE = 1500;
    /**
     * Thread pool executor.
     */
    private ThreadPoolExecutor executor;

    private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

    private EventSendPool() {
        // load the settings
        int queueSize = QUEUE_SIZE;
        int maxPoolSize = 1;
        int corePoolSize = 1;
        long keepAliveTime = 60;

        TimeUnit timeUnit = TimeUnit.SECONDS;

        boolean allowCoreThreadTimeOut = false;

        executor = new CustomThreadPoolExecutor(corePoolSize, maxPoolSize, keepAliveTime, timeUnit,
                new LinkedBlockingQueue<Runnable>(queueSize), new EventAbortPolicy()) {
            @Override
            protected void afterExecute(Runnable r, Throwable t) {
                try {
                    if (r instanceof CustomFutureTask<?> && ((CustomFutureTask<?>) r).getTask() instanceof EventSender) {
                        EventSender task = (EventSender) ((CustomFutureTask<?>) r).getTask();
                        if(task.getEvent() instanceof JavaAgentEventBean){
                            if (t != null) {
                                AgentInfo.getInstance().getJaHealthCheck().getEventStats().getEventSender().incrementError();
                            } else {
                                AgentInfo.getInstance().getJaHealthCheck().getEventStats().getEventSender().incrementCompleted();
                            }
                        }
                    }
//                    if (t != null) {
//                        AgentInfo.getInstance().getJaHealthCheck().getEventStats().getEventSender().incrementError();
//                    } else {
//                        AgentInfo.getInstance().getJaHealthCheck().getEventStats().getEventSender().incrementCompleted();
//                    }
                } catch (Throwable ignored){}
                super.afterExecute(r, t);
            }
        };
        executor.allowCoreThreadTimeOut(allowCoreThreadTimeOut);
        executor.setThreadFactory(new ThreadFactory() {
            @Override
            public Thread newThread(Runnable r) {
                Thread t = new Thread(Thread.currentThread().getThreadGroup(), r,
                        "NR-CSEC-EventSender");
                t.setDaemon(true);
                return t;
            }
        });
    }

    public int getMaxQueueSize() {
        return QUEUE_SIZE;
    }

    private static final class InstanceHolder {
        static final EventSendPool instance = new EventSendPool();
    }
    /**
     * @return the instance
     */
    public static EventSendPool getInstance() {
        return InstanceHolder.instance;
    }

    public void sendEvent(String event) {
        executor.submit(new EventSender(event));
    }

    public void sendEvent(JavaAgentEventBean event) {

        if(!event.getIsIASTRequest() && !AgentUsageMetric.isRASPProcessingActive()){
            AgentInfo.getInstance().getJaHealthCheck().getEventStats().getDroppedDueTo().incrementRaspProcessingDeactivated();
            return;
        }
        executor.submit(new EventSender(event));
        AgentInfo.getInstance().getJaHealthCheck().getEventStats().getEventSender().incrementSubmitted();
    }

    public void sendEvent(Object event) {
        executor.submit(new EventSender(event));
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
                                EventSendPool.class.getName());
                    }
                }
            } catch (InterruptedException e) {
            }
        }

    }

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
            if (r instanceof CustomFutureTask<?> && ((CustomFutureTask<?>) r).getTask() instanceof EventSender) {
                EventSender eventSender = (EventSender) ((CustomFutureTask<?>) r).getTask();
                if (eventSender.getEvent() instanceof JavaAgentEventBean) {
                    JavaAgentEventBean event = (JavaAgentEventBean) eventSender.getEvent();
                    if(event.getIsIASTRequest()){
                        String fuzzRequestId = event.getParentId();
                        if (event.getHttpRequest().getIsGrpc()) {
                            GrpcClientRequestReplayHelper.getInstance().getRejectedIds().add(fuzzRequestId);
                        } else {
                            RestRequestThreadPool.getInstance().getRejectedIds().add(fuzzRequestId);
                        }
                    }
                }
            }

            logger.log(LogLevel.FINER, "Event Send Task " + r.toString() + " rejected from  " + e.toString(), EventSendPool.class.getName());
            AgentInfo.getInstance().getJaHealthCheck().getEventStats().getEventSender().incrementRejected();
        }
    }

    public ThreadPoolExecutor getExecutor() {
        return executor;
    }

    public void reset() {
        executor.getQueue().clear();
        executor.purge();
    }
}
