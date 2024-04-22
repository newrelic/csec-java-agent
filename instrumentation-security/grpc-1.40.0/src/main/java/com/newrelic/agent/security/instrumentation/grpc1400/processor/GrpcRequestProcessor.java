package com.newrelic.agent.security.instrumentation.grpc1400.processor;

import com.newrelic.agent.security.instrumentation.grpc1400.client.GrpcClient;
import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GrpcClientRequestReplayHelper;
import com.newrelic.api.agent.security.schema.ControlCommandDto;
import com.newrelic.api.agent.security.utils.logging.LogLevel;

import java.util.concurrent.Callable;
import java.util.concurrent.Future;

public class GrpcRequestProcessor implements Callable<Object> {
    public static final String CALL_FAILED_REQUEST_S_REASON = "Call failed : request %s reason : %s ";
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

    public static void executeGrpcRequest(ControlCommandDto controlCommandDto) {
        Future<Object> future = GrpcRequestThreadPool.getInstance().executor
                .submit(new GrpcRequestProcessor(controlCommandDto, MAX_REPETITION));
        try {
            Object futureResult = future.get();
            if (futureResult instanceof Throwable) {
                NewRelicSecurity.getAgent().log(LogLevel.FINER, String.format(CALL_FAILED_REQUEST_S_REASON, controlCommandDto.getRequestBean(), ((Throwable) futureResult).getMessage()), (Throwable) futureResult, GrpcClient.class.getName());
                NewRelicSecurity.getAgent().reportIncident(LogLevel.WARNING,
                        String.format(CALL_FAILED_REQUEST_S_REASON, controlCommandDto.getId(), ((Throwable) futureResult).getMessage()),
                        (Throwable) futureResult, GrpcClient.class.getName());
                GrpcClientRequestReplayHelper.getInstance().addFuzzFailEventToQueue(controlCommandDto.getRequestBean(), (Throwable) futureResult);
            } else {
                GrpcClientRequestReplayHelper.getInstance().getPendingIds().remove(controlCommandDto.getId());
            }
        } catch (Throwable e) {
            NewRelicSecurity.getAgent().log(LogLevel.SEVERE, String.format(CALL_FAILED_REQUEST_S_REASON, controlCommandDto.getRequestBean(), e.getMessage()), e, GrpcRequestProcessor.class.getName());
            NewRelicSecurity.getAgent().reportIncident(LogLevel.SEVERE,
                    String.format(CALL_FAILED_REQUEST_S_REASON, controlCommandDto.getId(), e.getMessage()),
                    e, GrpcRequestProcessor.class.getName());
            GrpcClientRequestReplayHelper.getInstance().addFuzzFailEventToQueue(controlCommandDto.getRequestBean(), e);
        }
    }

    public ControlCommandDto getPartialControlCommand() {
        return controlCommandDto;
    }
}