package com.k2cybersecurity.intcodeagent.models.javaagent;

import com.k2cybersecurity.intcodeagent.websocket.JsonConverter;

public class ExitEventBean extends AgentBasicInfo {
    private String id;
    private String caseType;
    private String k2RequestIdentifier;

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

    public String getK2RequestIdentifier() {
        return k2RequestIdentifier;
    }

    public void setK2RequestIdentifier(String k2RequestIdentifier) {
        this.k2RequestIdentifier = k2RequestIdentifier;
    }

    @Override
    public String toString() {
        return JsonConverter.toJSON(this);
    }
}
