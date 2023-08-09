package com.newrelic.agent.security.instrumentator.httpclient;

import com.newrelic.agent.security.AgentInfo;
import com.newrelic.agent.security.intcodeagent.executor.CustomFutureTask;
import com.newrelic.agent.security.intcodeagent.filelogging.FileLoggerThreadPool;
import com.newrelic.agent.security.intcodeagent.filelogging.LogLevel;
import com.newrelic.agent.security.intcodeagent.models.IASTDataTransferRequest;
import com.newrelic.agent.security.intcodeagent.websocket.WSClient;
import com.newrelic.agent.security.intcodeagent.websocket.WSUtils;
import com.newrelic.agent.security.util.AgentUsageMetric;
import com.newrelic.api.agent.NewRelic;
import com.newrelic.api.agent.security.NewRelicSecurity;

import java.time.Instant;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import static com.newrelic.agent.security.instrumentator.utils.INRSettingsKey.SECURITY_POLICY_VULNERABILITY_SCAN_IAST_SCAN_PROBING_THRESHOLD;

public class IASTDataTransferRequestProcessor {
    private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();
    public static final String UNABLE_TO_SEND_IAST_DATA_REQUEST_DUE_TO_ERROR_S_S = "Unable to send IAST data request due to error: %s : %s";
    public static final String UNABLE_TO_SEND_IAST_DATA_REQUEST_DUE_TO_ERROR = "Unable to send IAST data request due to error: %s";

    private static ScheduledExecutorService executorService;

    private ScheduledFuture future;

    private static IASTDataTransferRequestProcessor instance;

    private static final Object syncLock = new Object();

    private final AtomicLong cooldownTillTimestamp = new AtomicLong();

    private final AtomicLong lastFuzzCCTimestamp = new AtomicLong();

    private void task() {
        IASTDataTransferRequest request = null;
        try {
            if(!AgentUsageMetric.isIASTRequestProcessingActive()){
                return;
            }

            if (WSUtils.getInstance().isReconnecting() ||
                    !WSClient.getInstance().isOpen()) {
                synchronized (WSUtils.getInstance()) {
                    RestRequestThreadPool.getInstance().isWaiting().set(true);
                    WSUtils.getInstance().wait();
                    RestRequestThreadPool.getInstance().isWaiting().set(false);
                }
            }
            long currentTimestamp = Instant.now().toEpochMilli();
            // Sleep if under cooldown
            long cooldownSleepTime = cooldownTillTimestamp.get() - currentTimestamp;
            if(cooldownSleepTime > 0) {
                Thread.sleep(cooldownSleepTime);
            }

            if (currentTimestamp - lastFuzzCCTimestamp.get() < TimeUnit.SECONDS.toMillis(5)) {
                return;
            }

            int currentFetchThreshold = NewRelic.getAgent().getConfig()
                    .getValue(SECURITY_POLICY_VULNERABILITY_SCAN_IAST_SCAN_PROBING_THRESHOLD, 300);

            int remainingRecordCapacity = RestRequestThreadPool.getInstance().getQueue().remainingCapacity();
            int currentRecordBacklog = RestRequestThreadPool.getInstance().getQueue().size();
            int batchSize = currentFetchThreshold - currentRecordBacklog;
            if(!AgentUsageMetric.isRASPProcessingActive()){
                batchSize /= 2;
            }

            if (batchSize > 100 && remainingRecordCapacity > batchSize) {
                request = new IASTDataTransferRequest(NewRelicSecurity.getAgent().getAgentUUID());
                request.setBatchSize(batchSize);
                request.setCompletedRequests(getEffectiveCompletedRequests());
                request.setPendingRequestIds(new HashSet<>(RestRequestThreadPool.getInstance().getPendingIds()));
                WSClient.getInstance().send(request.toString());
            }
        } catch (Throwable e) {
            logger.log(LogLevel.SEVERE, String.format(UNABLE_TO_SEND_IAST_DATA_REQUEST_DUE_TO_ERROR_S_S, e.toString(), e.getCause().toString()), this.getClass().getName());
            logger.log(LogLevel.FINEST, String.format(UNABLE_TO_SEND_IAST_DATA_REQUEST_DUE_TO_ERROR, request), e, this.getClass().getName());
        }
    }

    private Map<String, Set<String>> getEffectiveCompletedRequests() {
        Map<String, Set<String>> completedRequest = new HashMap<>(RestRequestThreadPool.getInstance().getProcessedIds());
        for (String rejectedId : RestRequestThreadPool.getInstance().getRejectedIds()) {
            completedRequest.remove(rejectedId);
        }
        RestRequestThreadPool.getInstance().getRejectedIds().clear();
        return completedRequest;
    }

    private IASTDataTransferRequestProcessor() {
        executorService = Executors.newSingleThreadScheduledExecutor(new ThreadFactory() {
            private final AtomicInteger threadNumber = new AtomicInteger(1);

            @Override
            public Thread newThread(Runnable r) {
                return new Thread(Thread.currentThread().getThreadGroup(), r,
                        "NewRelic-IASTDataTransferRequestProcessor-" + threadNumber.getAndIncrement());
            }
        });
    }

    public static IASTDataTransferRequestProcessor getInstance() {
        if(instance == null) {
            synchronized (syncLock) {
                if(instance == null) {
                    instance = new IASTDataTransferRequestProcessor();
                }
            }
        }
        return instance;
    }


    public void startDataRequestSchedule(long delay, TimeUnit timeUnit){
        try {
            stopDataRequestSchedule(true);
            future = executorService.scheduleWithFixedDelay(this::task, 0, delay, timeUnit);
        } catch (Throwable e){
            e.printStackTrace();
        }
    }

    public void stopDataRequestSchedule(boolean force){
        try {
            if (this.future != null) {
                future.cancel(force);
                future = null;
            }
        } catch (Throwable e) {
            e.printStackTrace();
        }
    }

    public void setCooldownTillTimestamp(long timestamp) {
        cooldownTillTimestamp.set(timestamp);
    }

    public void setLastFuzzCCTimestamp(long timestamp) {
        lastFuzzCCTimestamp.set(timestamp);
    }
}
