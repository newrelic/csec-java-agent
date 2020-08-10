package com.k2cybersecurity.intcodeagent.models.javaagent;

import com.k2cybersecurity.intcodeagent.websocket.JsonConverter;

public class FuzzFailEvent extends AgentBasicInfo {

    private String fuzzHeader;

    public FuzzFailEvent() {
        super();
    }

    public String getFuzzHeader() {
        return fuzzHeader;
    }

    public void setFuzzHeader(String fuzzHeader) {
        this.fuzzHeader = fuzzHeader;
    }

    @Override
    public String toString() {
        return JsonConverter.toJSON(this);
    }

}
