package com.newrelic.agent.security.instrumentator.httpclient;

import com.newrelic.agent.security.AgentInfo;
import com.newrelic.agent.security.intcodeagent.filelogging.FileLoggerThreadPool;
import com.newrelic.agent.security.intcodeagent.models.javaagent.FuzzFailEvent;
import com.newrelic.agent.security.intcodeagent.websocket.EventSendPool;
import com.newrelic.api.agent.security.instrumentation.helpers.GrpcClientRequestReplayHelper;
import com.newrelic.api.agent.security.instrumentation.helpers.ServletHelper;
import com.newrelic.api.agent.security.schema.FuzzRequestBean;

import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

public class MonitorGrpcFuzzFailRequestQueueThread {
    private final ExecutorService commonExecutor;
    private static Future future;

    private Runnable runnable = new Runnable() {
        public void run() {
            try {
                // TODO: Add to fuzz fail count in HC and remove FuzzFailEvent if not needed.
                Map<FuzzRequestBean, Throwable> fuzzFailMap = GrpcClientRequestReplayHelper.getInstance().getSingleRequestFromFuzzFailRequestQueue();
                FuzzRequestBean request = (FuzzRequestBean) fuzzFailMap.keySet().toArray()[0];
                FuzzFailEvent fuzzFailEvent = new FuzzFailEvent(AgentInfo.getInstance().getApplicationUUID());
                fuzzFailEvent.setFuzzHeader(request.getHeaders().get(ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID));
                EventSendPool.getInstance().sendEvent(fuzzFailEvent);
            } catch (InterruptedException e) {
            } finally {
                future = commonExecutor.submit(runnable);
            }
        }
    };

    private MonitorGrpcFuzzFailRequestQueueThread() {
        commonExecutor = Executors.newSingleThreadExecutor();
    }

    public static MonitorGrpcFuzzFailRequestQueueThread getInstance(){
        return InstanceHolder.instance;
    }

    private static final class InstanceHolder {
        static final MonitorGrpcFuzzFailRequestQueueThread instance = new MonitorGrpcFuzzFailRequestQueueThread();
    }

    public static void submitNewTask() {
        if (future == null){
            future = MonitorGrpcFuzzFailRequestQueueThread.getInstance().commonExecutor.submit(getInstance().runnable);
        }
    }

    public static boolean cancelTask() {
        if (future == null) {
            return true;
        }
        future.cancel(true);
        return true;
    }
}