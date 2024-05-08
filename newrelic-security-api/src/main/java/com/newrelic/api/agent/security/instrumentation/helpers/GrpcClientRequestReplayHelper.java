package com.newrelic.api.agent.security.instrumentation.helpers;

import com.newrelic.api.agent.security.schema.ControlCommandDto;
import com.newrelic.api.agent.security.schema.FuzzRequestBean;
import com.newrelic.api.agent.security.schema.StringUtils;

import java.util.Collections;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.atomic.AtomicBoolean;

public class GrpcClientRequestReplayHelper {
    private BlockingQueue<ControlCommandDto> requestQueue = new LinkedBlockingQueue<>(1000);
    private BlockingQueue<?> inProcessRequestQueue = new LinkedBlockingQueue(1000);
    private BlockingQueue<Map<FuzzRequestBean, Throwable>> fuzzFailRequestQueue = new LinkedBlockingQueue(1000);
    private boolean isGrpcRequestExecutorStarted = false;
    private final Map<String, Set<String>> processedIds = new ConcurrentHashMap();
    private final Set<String> pendingIds = ConcurrentHashMap.newKeySet();
    private final Set<String> rejectedIds = ConcurrentHashMap.newKeySet();
    private static final AtomicBoolean isWaiting = new AtomicBoolean(false);

    public static GrpcClientRequestReplayHelper getInstance(){
        return InstanceHolder.instance;
    }

    private static final class InstanceHolder {
        static final GrpcClientRequestReplayHelper instance = new GrpcClientRequestReplayHelper();
    }

    //TODO Update MicrosService Arch
    public void resetIASTProcessing() {
        rejectedIds.addAll(processedIds.keySet());
        processedIds.clear();
        pendingIds.clear();
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

    public Map<String, Set<String>> getProcessedIds() {
        return processedIds;
    }

    public Set<String> getRejectedIds() {
        return rejectedIds;
    }

    public Set<String> getPendingIds() {
        return pendingIds;
    }

    public void registerEventForProcessedCC(String controlCommandId, String eventId) {
        //TODO Update MicrosService Arch
        if(StringUtils.isAnyBlank(controlCommandId, eventId)){
            return;
        }
        Set<String> registeredEvents = processedIds.get(controlCommandId);
        if(registeredEvents != null) {
            registeredEvents.add(eventId);
        }
    }

    public void removeFromProcessedCC(String controlCommandId) {
        //TODO Update MicrosService Arch
        if(StringUtils.isNotBlank(controlCommandId)){
            processedIds.remove(controlCommandId);
        }
    }
}
