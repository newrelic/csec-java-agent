package com.newrelic.agent.security.intcodeagent.models.javaagent;

import com.newrelic.agent.security.AgentInfo;
import com.newrelic.agent.security.instrumentator.dispatcher.DispatcherPool;
import com.newrelic.agent.security.intcodeagent.websocket.JsonConverter;
import com.newrelic.api.agent.security.schema.operation.FileOperation;
import com.newrelic.api.agent.security.utils.logging.LogLevel;

public class ExitEventBean extends AgentBasicInfo {
    private String executionId;
    private String caseType;
    private String csecRequestIdentifier;
    private String applicationUUID;

    public ExitEventBean() {
        super();
    }

    public ExitEventBean(String executionId, String caseType) {
        this();
        this.executionId = executionId;
        this.caseType = caseType;
        this.applicationUUID = AgentInfo.getInstance().getApplicationUUID();
    }

    public String getExecutionId() {
        return executionId;
    }

    public void setExecutionId(String executionId) {
        this.executionId = executionId;
    }

    public String getCaseType() {
        return caseType;
    }

    public void setCaseType(String caseType) {
        this.caseType = caseType;
    }

    public String getCsecRequestIdentifier() {
        return csecRequestIdentifier;
    }

    public void setCsecRequestIdentifier(String csecRequestIdentifier) {
        this.csecRequestIdentifier = csecRequestIdentifier;
    }

    public String getApplicationUUID() {
        return applicationUUID;
    }

    public void setApplicationUUID(String applicationUUID) {
        this.applicationUUID = applicationUUID;
    }

    @Override
    public String toString() {
        return JsonConverter.toJSON(this);
    }
}
