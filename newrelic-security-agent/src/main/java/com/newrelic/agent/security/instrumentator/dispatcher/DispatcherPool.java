package com.newrelic.agent.security.instrumentator.dispatcher;

import com.newrelic.agent.security.AgentInfo;
import com.newrelic.agent.security.intcodeagent.filelogging.FileLoggerThreadPool;
import com.newrelic.agent.security.intcodeagent.filelogging.LogLevel;
import com.newrelic.agent.security.intcodeagent.logging.IAgentConstants;
import com.newrelic.agent.security.intcodeagent.models.javaagent.ExitEventBean;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.SecurityMetaData;
import org.apache.commons.lang3.StringUtils;

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
            AgentInfo.getInstance().getJaHealthCheck().incrementDropCount();
            AgentInfo.getInstance().getJaHealthCheck().incrementProcessedCount();
//			logger.log(LogLevel.FINE,"Event Task " + r.toString() + " rejected from  " + e.toString(), EventThreadPool.class.getName());
        }
    }

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
                            AgentInfo.getInstance().getJaHealthCheck().incrementProcessedCount();
                            future.get();
                        }
                    } catch (Throwable e) {
                        AgentInfo.getInstance().getJaHealthCheck().incrementDropCount();
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


    public void dispatchEvent(AbstractOperation operation, SecurityMetaData securityMetaData) {
        if (executor.isShutdown()) {
            return;
        }
        if (!operation.isEmpty() && securityMetaData.getFuzzRequestIdentifier().getK2Request()) {
            if (StringUtils.equals(securityMetaData.getFuzzRequestIdentifier().getApiRecordId(), operation.getApiID()) && StringUtils.equals(securityMetaData.getFuzzRequestIdentifier().getNextStage().getStatus(), IAgentConstants.VULNERABLE)) {
                eid.add(operation.getExecutionId());
            }
        }
        this.executor.submit(new Dispatcher(operation, new SecurityMetaData(securityMetaData)));
    }

    public void dispatchExitEvent(ExitEventBean exitEventBean) {
        if (executor.isShutdown()) {
            return;
        }
        this.executor.submit(new Dispatcher(exitEventBean));
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
                                DispatcherPool.class.getName());
                    }
                }
            } catch (InterruptedException e) {
            }
        }

    }

}
