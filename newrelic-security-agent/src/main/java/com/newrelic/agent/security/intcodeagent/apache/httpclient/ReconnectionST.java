package com.newrelic.agent.security.intcodeagent.apache.httpclient;

import com.newrelic.agent.security.AgentInfo;
import com.newrelic.agent.security.intcodeagent.communication.ConnectionFactory;
import com.newrelic.agent.security.intcodeagent.filelogging.FileLoggerThreadPool;
import com.newrelic.agent.security.intcodeagent.utils.CommonUtils;
import com.newrelic.api.agent.security.utils.logging.LogLevel;

import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

public class ReconnectionST {

    private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

    private static ScheduledExecutorService scheduledService;

    private ScheduledFuture futureTask;

    private static class InstanceHolder {
        private static final ReconnectionST INSTANCE = new ReconnectionST();
    }

    public static ReconnectionST getInstance() {
        return InstanceHolder.INSTANCE;
    }

    private ReconnectionST() {
        instantiateScheduler();
    }

    private final Runnable runnable = new Runnable() {
        @Override
        public void run() {
            try {
                AgentInfo.getInstance().getJaHealthCheck().getSchedulerRuns().incrementWebsocketReconnector();
                if (!ConnectionFactory.getInstance().getSecurityConnection().isConnected()) {
                    logger.log(LogLevel.INFO, "Http is marked disconnected, reconnecting ...", ReconnectionST.class.getName());
                    ConnectionFactory.getInstance().getSecurityConnection().ping();
                }
            } catch (Throwable t){
                logger.log(LogLevel.SEVERE, "Error while Http reconnection : " + t.getMessage() + " : " + t.getCause(), ReconnectionST.class.getName());
                logger.log(LogLevel.FINER, "Error while Http reconnection", t, ReconnectionST.class.getName());
                logger.postLogMessageIfNecessary(LogLevel.SEVERE, "Error while Http reconnection : " + t.getMessage() + " : " + t.getCause(), t, ReconnectionST.class.getName());
            } finally {
                submitNewTaskSchedule();
            }
        }
    };

    private void instantiateScheduler() {
        scheduledService = Executors.newSingleThreadScheduledExecutor(new ThreadFactory() {
            private final AtomicInteger threadNumber = new AtomicInteger(1);

            @Override
            public Thread newThread(Runnable r) {
                return new Thread(Thread.currentThread().getThreadGroup(), r,
                        "HttpReconnectionST_" + threadNumber.getAndIncrement());
            }
        });
    }

    public void submitNewTaskSchedule() {
        int delay = CommonUtils.generateSecureRandomBetween(5, 15);
        futureTask = scheduledService.schedule(runnable, delay, TimeUnit.SECONDS);
    }

    public void cancelTask() {
        if(futureTask != null) {
            futureTask.cancel(false);
        }
    }

    public void shutdown() {
        if(scheduledService != null) {
            scheduledService.shutdown();
        }
    }


}
