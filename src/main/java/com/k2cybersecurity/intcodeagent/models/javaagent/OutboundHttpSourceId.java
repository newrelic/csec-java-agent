package com.k2cybersecurity.intcodeagent.models.javaagent;

import com.k2cybersecurity.intcodeagent.websocket.JsonConverter;

import java.util.Objects;

public class OutboundHttpSourceId {

    private String applicationUUID;

    private String contextPath;

    private String serverPort;

    private String target;

    public OutboundHttpSourceId(String applicationUUID, String contextPath, String serverPort, String target) {
        this.applicationUUID = applicationUUID;
        this.contextPath = contextPath;
        this.serverPort = serverPort;
        this.target = target;
    }

    public String getApplicationUUID() {
        return applicationUUID;
    }

    public void setApplicationUUID(String applicationUUID) {
        this.applicationUUID = applicationUUID;
    }

    public String getContextPath() {
        return contextPath;
    }

    public void setContextPath(String contextPath) {
        this.contextPath = contextPath;
    }

    public String getServerPort() {
        return serverPort;
    }

    public void setServerPort(String serverPort) {
        this.serverPort = serverPort;
    }

    public String getTarget() {
        return target;
    }

    public void setTarget(String target) {
        this.target = target;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        OutboundHttpSourceId that = (OutboundHttpSourceId) o;
        return Objects.equals(applicationUUID, that.applicationUUID) &&
                Objects.equals(contextPath, that.contextPath) &&
                Objects.equals(target, that.target) &&
                Objects.equals(serverPort, that.serverPort);
    }

    @Override
    public int hashCode() {
        return Objects.hash(applicationUUID, contextPath, serverPort, target);
    }

    @Override
    public String toString() {
        return JsonConverter.toJSON(this);
    }
}
