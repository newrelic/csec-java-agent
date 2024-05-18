package com.newrelic.agent.security.instrumentation.grpc140.processor;

import com.newrelic.agent.security.instrumentation.grpc140.client.GrpcClient;
import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GrpcClientRequestReplayHelper;
import com.newrelic.api.agent.security.schema.ControlCommandDto;
import com.newrelic.api.agent.security.utils.logging.LogLevel;

import java.util.concurrent.Callable;
import java.util.concurrent.Future;

public class GrpcRequestProcessor implements Callable<Object> {
    public static final String CALL_FAILED_REQUEST_S_REASON = "Call failed : request %s reason : ";
    private ControlCommandDto controlCommandDto;
    private int repeatCount;
    private static final int MAX_REPETITION = 3;

    private boolean isSuccessful = false;

    private int responseCode;

    private boolean exceptionRaised = false;

    private Throwable error;

    public GrpcRequestProcessor(ControlCommandDto controlCommandDto, int repeatCount) {
        this.controlCommandDto = controlCommandDto;
        this.repeatCount = repeatCount;
    }

    @Override
    public Object call() throws Exception {
        return GrpcClient.getInstance().fireRequest(this);
    }

    public static void executeGrpcRequest(ControlCommandDto controlCommandDto) {
        GrpcRequestThreadPool.getInstance().executor
                .submit(new GrpcRequestProcessor(controlCommandDto, MAX_REPETITION));
    }

    public ControlCommandDto getPartialControlCommand() {
        return controlCommandDto;
    }

    public boolean isSuccessful() {
        return isSuccessful;
    }

    public void setSuccessful(boolean successful) {
        isSuccessful = successful;
    }

    public int getResponseCode() {
        return responseCode;
    }

    public void setResponseCode(int responseCode) {
        this.responseCode = responseCode;
    }

    public boolean isExceptionRaised() {
        return exceptionRaised;
    }

    public void setExceptionRaised(boolean exceptionRaised) {
        this.exceptionRaised = exceptionRaised;
    }

    public Throwable getError() {
        return error;
    }

    public void setError(Throwable error) {
        this.error = error;
    }

    public ControlCommandDto getControlCommandDto() {
        return controlCommandDto;
    }

    public int getRepeatCount() {
        return repeatCount;
    }
}