package com.newrelic.agent.security.instrumentation.grpc1400.processor;

import com.newrelic.agent.security.instrumentation.grpc1400.client.GrpcClient;
import com.newrelic.api.agent.security.schema.ControlCommandDto;

import java.util.concurrent.Callable;

public class GrpcRequestProcessor implements Callable<Object> {
    public static final String CALL_FAILED_REQUEST_S_REASON = "Call failed : request %s reason : %s ";
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
        GrpcClient.getInstance().fireRequest(this);
        return this;
    }

    public static void executeGrpcRequest(ControlCommandDto controlCommandDto) {
        GrpcRequestThreadPool.getInstance().executor
                .submit(new GrpcRequestProcessor(controlCommandDto, MAX_REPETITION));
    }

    public ControlCommandDto getPartialControlCommand() {
        return controlCommandDto;
    }

    public void setSuccessful(boolean successful) {
        isSuccessful = successful;
    }

    public void setResponseCode(int responseCode) {
        this.responseCode = responseCode;
    }

    public void setExceptionRaised(boolean exceptionRaised) {
        this.exceptionRaised = exceptionRaised;
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

    public boolean isSuccessful() {
        return isSuccessful;
    }

    public int getResponseCode() {
        return responseCode;
    }

    public boolean isExceptionRaised() {
        return exceptionRaised;
    }

    public Throwable getError() {
        return error;
    }
}