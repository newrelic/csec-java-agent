package com.k2cybersecurity.intcodeagent.models.javaagent;

import com.k2cybersecurity.intcodeagent.websocket.JsonConverter;

public class ExitEventBean extends AgentBasicInfo {
    private String id;
    private String caseType;

    public ExitEventBean() {
        super();
    }

    public ExitEventBean(String id, String caseType) {
        this();
        this.id = id;
        this.caseType = caseType;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getCaseType() {
        return caseType;
    }

    public void setCaseType(String caseType) {
        this.caseType = caseType;
    }

    @Override
    public String toString() {
        return JsonConverter.toJSON(this);
    }
}
