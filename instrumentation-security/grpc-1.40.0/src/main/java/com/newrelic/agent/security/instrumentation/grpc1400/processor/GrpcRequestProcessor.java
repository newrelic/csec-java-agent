package com.newrelic.agent.security.instrumentation.grpc1400.processor;

import com.newrelic.agent.security.instrumentation.grpc1400.client.GrpcClient;
import com.newrelic.api.agent.security.instrumentation.helpers.GrpcClientRequestReplayHelper;
import com.newrelic.api.agent.security.schema.ControlCommandDto;

import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;

public class GrpcRequestProcessor implements Callable<Object> {
    private ControlCommandDto controlCommandDto;
    private int repeatCount;
    private static final int MAX_REPETITION = 3;

    public GrpcRequestProcessor(ControlCommandDto controlCommandDto, int repeatCount) {
        this.controlCommandDto = controlCommandDto;
        this.repeatCount = repeatCount;
    }

    @Override
    public Object call() throws Exception {
        return GrpcClient.getInstance().fireRequest(controlCommandDto, repeatCount);
    }

    public static void executeGrpcRequest(ControlCommandDto request) {
        Future<Object> future = GrpcRequestThreadPool.getInstance().executor
                .submit(new GrpcRequestProcessor(request, MAX_REPETITION));
        try {
            Object futureResult = future.get();
            if (futureResult instanceof Throwable) {
                GrpcClientRequestReplayHelper.getInstance().addFuzzFailEventToQueue(request.getRequestBean(), (Throwable) futureResult);
            } else {
                GrpcClientRequestReplayHelper.getInstance().getPendingIds().remove(request.getId());
            }
        } catch (InterruptedException | ExecutionException e) {
            GrpcClientRequestReplayHelper.getInstance().addFuzzFailEventToQueue(request.getRequestBean(), e);
        }
    }

    public ControlCommandDto getPartialControlCommand() {
        return controlCommandDto;
    }
}