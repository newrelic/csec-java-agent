package com.k2cybersecurity.intcodeagent.models.javaagent;

import com.k2cybersecurity.intcodeagent.websocket.JsonConverter;

import java.util.Collection;

public class HttpConnectionStat extends AgentBasicInfo {

    private Collection<OutBoundHttp> httpConnections;

    private String applicationUUID;

    private Boolean isCached;

    public HttpConnectionStat(Collection<OutBoundHttp> httpConnections, String applicationUUID, Boolean isCached) {
        this.httpConnections = httpConnections;
        this.applicationUUID = applicationUUID;
        this.isCached = isCached;
    }

    public void setHttpConnections(Collection<OutBoundHttp> httpConnections) {
        this.httpConnections = httpConnections;
    }

    public Collection<OutBoundHttp> getHttpConnections() {
        return httpConnections;
    }

    public Boolean getCached() {
        return isCached;
    }

    public void setCached(Boolean cached) {
        isCached = cached;
    }

    public String getApplicationUUID() {
        return applicationUUID;
    }

    public void setApplicationUUID(String applicationUUID) {
        this.applicationUUID = applicationUUID;
    }

    public String toString() {
        return JsonConverter.toJSON(this);
    }

}
