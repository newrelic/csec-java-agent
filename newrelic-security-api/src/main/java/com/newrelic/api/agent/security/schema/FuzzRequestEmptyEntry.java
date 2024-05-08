package com.newrelic.api.agent.security.schema;

public class FuzzRequestEmptyEntry {

    private String originAppUuid;

    private String originEntityGuid;

    private String controlCommandId;

    public FuzzRequestEmptyEntry(String originAppUuid, String originEntityGuid, String controlCommandId) {
        this.originAppUuid = originAppUuid;
        this.originEntityGuid = originEntityGuid;
        this.controlCommandId = controlCommandId;
    }

    public String getOriginAppUuid() {
        return originAppUuid;
    }

    public void setOriginAppUuid(String originAppUuid) {
        this.originAppUuid = originAppUuid;
    }

    public String getOriginEntityGuid() {
        return originEntityGuid;
    }

    public void setOriginEntityGuid(String originEntityGuid) {
        this.originEntityGuid = originEntityGuid;
    }

    public String getControlCommandId() {
        return controlCommandId;
    }

    public void setControlCommandId(String controlCommandId) {
        this.controlCommandId = controlCommandId;
    }
}
