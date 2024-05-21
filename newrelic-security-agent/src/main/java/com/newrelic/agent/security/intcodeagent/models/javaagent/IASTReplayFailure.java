package com.newrelic.agent.security.intcodeagent.models.javaagent;

import com.newrelic.agent.security.intcodeagent.websocket.JsonConverter;

public class IASTReplayFailure {

    private String apiId;
    private String nrCsecFuzzRequestId;
    private String controlCommandId;
    private String failureMessage;
    private LogMessageException error;

    public IASTReplayFailure() {
    }

    public IASTReplayFailure(String apiId, String nrCsecFuzzRequestId, String controlCommandId, String failureMessage, LogMessageException error) {
        this.apiId = apiId;
        this.nrCsecFuzzRequestId = nrCsecFuzzRequestId;
        this.controlCommandId = controlCommandId;
        this.failureMessage = failureMessage;
        this.error = error;
    }

    public String getApiId() {
        return apiId;
    }

    public void setApiId(String apiId) {
        this.apiId = apiId;
    }

    public String getNrCsecFuzzRequestId() {
        return nrCsecFuzzRequestId;
    }

    public void setNrCsecFuzzRequestId(String nrCsecFuzzRequestId) {
        this.nrCsecFuzzRequestId = nrCsecFuzzRequestId;
    }

    public String getControlCommandId() {
        return controlCommandId;
    }

    public void setControlCommandId(String controlCommandId) {
        this.controlCommandId = controlCommandId;
    }

    public String getFailureMessage() {
        return failureMessage;
    }

    public void setFailureMessage(String failureMessage) {
        this.failureMessage = failureMessage;
    }

    public LogMessageException getError() {
        return error;
    }

    public void setError(LogMessageException error) {
        this.error = error;
    }

    public String toString() {
        return JsonConverter.toJSON(this);
    }
}
