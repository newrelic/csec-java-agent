package com.newrelic.agent.security.instrumentator.httpclient;

import com.newrelic.agent.security.AgentConfig;
import com.newrelic.agent.security.AgentInfo;
import com.newrelic.agent.security.instrumentator.utils.INRSettingsKey;
import com.newrelic.agent.security.intcodeagent.filelogging.FileLoggerThreadPool;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import com.newrelic.agent.security.intcodeagent.models.IASTDataTransferRequest;
import com.newrelic.agent.security.intcodeagent.websocket.JsonConverter;
import com.newrelic.agent.security.intcodeagent.websocket.WSClient;
import com.newrelic.agent.security.intcodeagent.websocket.WSUtils;
import com.newrelic.agent.security.util.AgentUsageMetric;
import com.newrelic.api.agent.NewRelic;
import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GrpcClientRequestReplayHelper;
import org.apache.commons.lang3.StringUtils;

import java.time.Instant;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
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
                    GrpcClientRequestReplayHelper.getInstance().isWaiting().set(true);
                    WSUtils.getInstance().wait();
                    RestRequestThreadPool.getInstance().isWaiting().set(false);
                    GrpcClientRequestReplayHelper.getInstance().isWaiting().set(false);
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

            int remainingRecordCapacityRest = RestRequestThreadPool.getInstance().getQueue().remainingCapacity();
            int currentRecordBacklogRest = RestRequestThreadPool.getInstance().getQueue().size();
            int remainingRecordCapacityGrpc = GrpcClientRequestReplayHelper.getInstance().getRequestQueue().remainingCapacity();
            int currentRecordBacklogGrpc = GrpcClientRequestReplayHelper.getInstance().getRequestQueue().size();

            int currentRecordBacklog = Math.max(currentRecordBacklogRest, currentRecordBacklogGrpc);
            int remainingRecordCapacity = Math.min(remainingRecordCapacityRest, remainingRecordCapacityGrpc);

            int batchSize = currentFetchThreshold - currentRecordBacklog;
            if(!AgentUsageMetric.isRASPProcessingActive()){
                batchSize /= 2;
            }

            if (batchSize > 100 && remainingRecordCapacity > batchSize) {
                request = new IASTDataTransferRequest(NewRelicSecurity.getAgent().getAgentUUID());
                if (AgentConfig.getInstance().getConfig().getCustomerInfo() != null) {
                    request.setAppAccountId(AgentConfig.getInstance().getConfig().getCustomerInfo().getAccountId());
                }
                request.setAppEntityGuid(AgentInfo.getInstance().getLinkingMetadata().getOrDefault(INRSettingsKey.NR_ENTITY_GUID, StringUtils.EMPTY));

                request.setBatchSize(batchSize);
                request.setCompletedRequests(getEffectiveCompletedRequests());

                HashSet<String> pendingRequestIds = new HashSet<>();
                pendingRequestIds.addAll(RestRequestThreadPool.getInstance().getPendingIds());
                pendingRequestIds.addAll(GrpcClientRequestReplayHelper.getInstance().getPendingIds());
                request.setPendingRequestIds(pendingRequestIds);
                WSClient.getInstance().send(request.toString());
            }
        } catch (Throwable e) {
            logger.log(LogLevel.SEVERE, String.format(UNABLE_TO_SEND_IAST_DATA_REQUEST_DUE_TO_ERROR_S_S, e.toString(), e.getCause().toString()), this.getClass().getName());
            logger.log(LogLevel.FINEST, String.format(UNABLE_TO_SEND_IAST_DATA_REQUEST_DUE_TO_ERROR, request), e, this.getClass().getName());
            logger.postLogMessageIfNecessary(LogLevel.SEVERE, String.format(UNABLE_TO_SEND_IAST_DATA_REQUEST_DUE_TO_ERROR, JsonConverter.toJSON(request)), e, this.getClass().getName());
        }
    }

    private Map<String, Set<String>> getEffectiveCompletedRequests() {
        Map<String, Set<String>> completedRequest = new HashMap<>();
        completedRequest.putAll(RestRequestThreadPool.getInstance().getProcessedIds());
        completedRequest.putAll(GrpcClientRequestReplayHelper.getInstance().getProcessedIds());
        for (String rejectedId : RestRequestThreadPool.getInstance().getRejectedIds()) {
            completedRequest.remove(rejectedId);
        }
        RestRequestThreadPool.getInstance().getRejectedIds().clear();
        for (String rejectedId : GrpcClientRequestReplayHelper.getInstance().getRejectedIds()) {
            completedRequest.remove(rejectedId);
        }
        GrpcClientRequestReplayHelper.getInstance().getRejectedIds().clear();
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
            long initialDelay = AgentConfig.getInstance().getAgentMode().getScanSchedule().getDataCollectionTime().toInstant().getEpochSecond() - Instant.now().getEpochSecond();
            if(initialDelay < 0){
                initialDelay = 0;
            }
            logger.log(LogLevel.INFO, String.format("IAST data pull request is scheduled at %s", AgentConfig.getInstance().getAgentMode().getScanSchedule().getDataCollectionTime()), IASTDataTransferRequestProcessor.class.getName());
            future = executorService.scheduleWithFixedDelay(this::task, initialDelay, delay, timeUnit);
        } catch (Throwable ignored){}
    }

    public void stopDataRequestSchedule(boolean force){
        try {
            if (this.future != null) {
                future.cancel(force);
                future = null;
            }
        } catch (Throwable ignored) {}
    }

    public void setCooldownTillTimestamp(long timestamp) {
        cooldownTillTimestamp.set(timestamp);
    }

    public void setLastFuzzCCTimestamp(long timestamp) {
        lastFuzzCCTimestamp.set(timestamp);
    }
}
