package com.newrelic.agent.security.intcodeagent.models.javaagent;

import com.newrelic.agent.security.AgentInfo;
import com.newrelic.agent.security.intcodeagent.websocket.JsonConverter;

public class ExitEventBean extends AgentBasicInfo {
    private String executionId;
    private String caseType;
    private String nrRequestIdentifier;
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

    public String getNRRequestIdentifier() {
        return nrRequestIdentifier;
    }

    public void setNRRequestIdentifier(String nrRequestIdentifier) {
        this.nrRequestIdentifier = nrRequestIdentifier;
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
