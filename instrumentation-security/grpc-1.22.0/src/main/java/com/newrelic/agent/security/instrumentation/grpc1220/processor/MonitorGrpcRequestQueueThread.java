package com.newrelic.agent.security.instrumentation.grpc1220.processor;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GrpcClientRequestReplayHelper;
import com.newrelic.api.agent.security.schema.ControlCommandDto;
import com.newrelic.api.agent.security.utils.logging.LogLevel;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

public class MonitorGrpcRequestQueueThread {
    private final ExecutorService commonExecutor;
    private final int queueSize = 1000;
    private final int maxPoolSize = 5;
    private final int corePoolSize = 3;
    private final long keepAliveTime = 10;
    private final TimeUnit timeUnit = TimeUnit.SECONDS;
    private static Future future;

    private Runnable runnable = new Runnable() {
        public void run() {
            try {
                if (GrpcRequestThreadPool.getInstance().executor.getQueue().remainingCapacity()>0) {
                    ControlCommandDto controlCommandDto = GrpcClientRequestReplayHelper.getInstance().getSingleRequestFromRequestQueue();
                    if (controlCommandDto != null) {
                        GrpcRequestProcessor.executeGrpcRequest(controlCommandDto);
                    }
                } else {
                    NewRelicSecurity.getAgent().log(LogLevel.WARNING, "gRPC request processing queue is full.", this.getClass().getName());
                }
            } catch (InterruptedException e) {
                NewRelicSecurity.getAgent().log(LogLevel.SEVERE, e.getMessage(), e, this.getClass().getName());
                NewRelicSecurity.getAgent().reportIncident(LogLevel.SEVERE, e.getMessage(), e, this.getClass().getName());
            } finally {
                future = commonExecutor.submit(runnable);
            }
        }
    };

    private MonitorGrpcRequestQueueThread() {
        LinkedBlockingQueue<Runnable> processQueue = new LinkedBlockingQueue<>(queueSize);
        commonExecutor = new ThreadPoolExecutor(corePoolSize, maxPoolSize, keepAliveTime, timeUnit, processQueue, new EventAbortPolicy()) {
            @Override
            protected void afterExecute(Runnable r, Throwable t) {
                super.afterExecute(r, t);
            }

            @Override
            protected void beforeExecute(Thread t, Runnable r) {
                super.beforeExecute(t, r);
            }

        };
    }

    public static MonitorGrpcRequestQueueThread getInstance(){
        return InstanceHolder.instance;
    }

    private static final class InstanceHolder {
        static final MonitorGrpcRequestQueueThread instance = new MonitorGrpcRequestQueueThread();
    }

    public static void submitNewTask() {
        if (future == null){
            future = MonitorGrpcRequestQueueThread.getInstance().commonExecutor.submit(getInstance().runnable);
        }
        GrpcClientRequestReplayHelper.getInstance().setGrpcRequestExecutorStarted(true);
    }

    public static boolean cancelTask() {
        if (future == null) {
            return true;
        }
        future.cancel(true);
        return true;
    }
}