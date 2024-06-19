package com.newrelic.api.agent.security.instrumentation.helpers;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.schema.ControlCommandDto;
import com.newrelic.api.agent.security.schema.FuzzRequestBean;
import com.newrelic.api.agent.security.schema.StringUtils;
import com.newrelic.api.agent.security.utils.logging.LogLevel;

import java.util.Collections;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

public class GrpcClientRequestReplayHelper {
    private BlockingQueue<ControlCommandDto> requestQueue = new LinkedBlockingQueue<>(1000);
    private BlockingQueue<?> inProcessRequestQueue = new LinkedBlockingQueue(1000);
    private BlockingQueue<Map<FuzzRequestBean, Throwable>> fuzzFailRequestQueue = new LinkedBlockingQueue(1000);
    private boolean isGrpcRequestExecutorStarted = false;

    private final Set<String> rejectedIds = ConcurrentHashMap.newKeySet();

    private Set<String> completedReplay = ConcurrentHashMap.newKeySet();

    private Set<String> errorInReplay = ConcurrentHashMap.newKeySet();

    private Set<String> clearFromPending = ConcurrentHashMap.newKeySet();

    private AtomicInteger replayRequestGenerated = new AtomicInteger();

    private AtomicInteger replayRequestExecuted = new AtomicInteger();

    private AtomicInteger replayRequestSucceeded = new AtomicInteger();

    private AtomicInteger replayRequestFailed = new AtomicInteger();

    public int incrementReplayRequestGenerated() {
        return replayRequestGenerated.incrementAndGet();
    }

    public int incrementReplayRequestExecuted() {
        return replayRequestExecuted.incrementAndGet();
    }

    public int incrementReplayRequestSucceeded() {
        return replayRequestSucceeded.incrementAndGet();
    }

    public int incrementReplayRequestFailed() {
        return replayRequestFailed.incrementAndGet();
    }

    public int getReplayRequestGenerated() {
        return replayRequestGenerated.get();
    }

    public int getReplayRequestExecuted() {
        return replayRequestExecuted.get();
    }

    public int getReplayRequestSucceeded() {
        return replayRequestSucceeded.get();
    }

    public int getReplayRequestFailed() {
        return replayRequestFailed.get();
    }

    public void resetReplayRequestMetric() {
        replayRequestGenerated.set(0);
        replayRequestExecuted.set(0);
        replayRequestSucceeded.set(0);
        replayRequestFailed.set(0);
    }

    /**
     * "generatedEvents":
     *     {
     *         "ORIGIN_APPUUID_1" : {"FUZZ_ID_1":["EVENT_ID_1"], "FUZZ_ID_2":["EVENT_ID_2"]},
     *     }
     * */
    private final Map<String, Map<String, Set<String>>> generatedEvent = new ConcurrentHashMap();

    private static final AtomicBoolean isWaiting = new AtomicBoolean(false);

    public static GrpcClientRequestReplayHelper getInstance(){
        return InstanceHolder.instance;
    }

    private static final class InstanceHolder {
        static final GrpcClientRequestReplayHelper instance = new GrpcClientRequestReplayHelper();
    }

    private void getAllControlCommandID(Map<String, Map<String, Set<String>>> generatedEvents) {
        if(generatedEvents == null || generatedEvents.isEmpty()) {
            return;
        }

        for (Map<String, Set<String>> applicationMap : generatedEvents.values()) {
            rejectedIds.addAll(applicationMap.keySet());
        }
    }

    public void resetIASTProcessing() {
        getAllControlCommandID(generatedEvent);
        generatedEvent.clear();
        completedReplay.clear();
        clearFromPending.clear();
        errorInReplay.clear();
        requestQueue.clear();
    }

    public BlockingQueue<ControlCommandDto> getRequestQueue() {
        return requestQueue;
    }

    public void addToRequestQueue(ControlCommandDto request) {
        requestQueue.add(request);
    }

    public void removeFromRequestQueue(ControlCommandDto request) {
        requestQueue.remove(request);
    }

    public ControlCommandDto getSingleRequestFromRequestQueue() throws InterruptedException {
        return requestQueue.take();
    }

    public BlockingQueue<?> getInProcessRequestQueue() {
        return inProcessRequestQueue;
    }

    public void setInProcessRequestQueue(BlockingQueue<?> queue) {
        inProcessRequestQueue = queue;
    }

    public boolean isGrpcRequestExecutorStarted() {
        return isGrpcRequestExecutorStarted;
    }

    public void setGrpcRequestExecutorStarted(boolean grpcRequestExecutorStarted) {
        isGrpcRequestExecutorStarted = grpcRequestExecutorStarted;
    }

    public AtomicBoolean isWaiting() {
        return isWaiting;
    }

    public void addFuzzFailEventToQueue(FuzzRequestBean requestBean, Throwable e){
        fuzzFailRequestQueue.add(Collections.singletonMap(requestBean, e));
    }

    public Map<FuzzRequestBean, Throwable> getSingleRequestFromFuzzFailRequestQueue() throws InterruptedException {
        return fuzzFailRequestQueue.take();
    }

    public Set<String> getRejectedIds() {
        return rejectedIds;
    }

    public void registerEventForProcessedCC(String controlCommandId, String eventId, String originAppUuid) {
        if(StringUtils.isAnyBlank(controlCommandId, eventId)){
            return;
        }
        if(!generatedEvent.containsKey(originAppUuid)){
            NewRelicSecurity.getAgent().log(LogLevel.FINE, String.format("Entry from map of generatedEvents for %s is missing. generatedEvents are : %s", originAppUuid, generatedEvent), GrpcClientRequestReplayHelper.class.getName());
        }

        if(generatedEvent.get(originAppUuid).containsKey(controlCommandId)) {
            generatedEvent.get(originAppUuid).get(controlCommandId).add(eventId);
        }
    }

    public Set<String> getCompletedReplay() {
        return completedReplay;
    }

    public void setCompletedReplay(Set<String> completedReplay) {
        this.completedReplay = completedReplay;
    }

    public Set<String> getErrorInReplay() {
        return errorInReplay;
    }

    public void setErrorInReplay(Set<String> errorInReplay) {
        this.errorInReplay = errorInReplay;
    }

    public Set<String> getClearFromPending() {
        return clearFromPending;
    }

    public void setClearFromPending(Set<String> clearFromPending) {
        this.clearFromPending = clearFromPending;
    }

    public Map<String, Map<String, Set<String>>> getGeneratedEvent() {
        return generatedEvent;
    }
}
