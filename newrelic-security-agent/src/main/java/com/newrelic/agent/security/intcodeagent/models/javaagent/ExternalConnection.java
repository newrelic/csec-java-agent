package com.newrelic.agent.security.intcodeagent.models.javaagent;

import com.newrelic.agent.security.intcodeagent.websocket.JsonConverter;

import java.util.Objects;

public class ExternalConnection {

    private String host;

    private int port;

    private String connectionUrl;

    private String ipAddress;

    private String type;

    private String module;

    public ExternalConnection() {

    }

    public ExternalConnection(String host, int port, String connectionUrl, String ipAddress, String type, String module) {
        this.host = host;
        this.port = port;
        this.connectionUrl = connectionUrl;
        this.ipAddress = ipAddress;
        this.type = type;
        this.module = module;
    }

    public String getHost() {
        return host;
    }

    public int getPort() {
        return port;
    }

    public String getConnectionUrl() {
        return connectionUrl;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public String getType() {
        return type;
    }

    public void setHost(String host) {
        this.host = host;
    }

    public void setPort(int port) {
        this.port = port;
    }

    public void setConnectionUrl(String connectionUrl) {
        this.connectionUrl = connectionUrl;
    }

    public void setIpAddress(String ipAddress) {
        this.ipAddress = ipAddress;
    }

    public void setType(String type) {
        this.type = type;
    }

    public String getModule() {
        return module;
    }

    public void setModule(String module) {
        this.module = module;
    }

    public boolean isEmpty() {
        if (host == null || connectionUrl == null || port == 0 || type == null) {
            return true;
        } else if (host.isEmpty() || connectionUrl.isEmpty() || type.isEmpty()) {
            return true;
        }
        return false;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj instanceof ExternalConnection) {
            ExternalConnection connection = (ExternalConnection) obj;
            return Objects.equals(host, connection.host) && Objects.equals(port, connection.port) && Objects.equals(connectionUrl, connection.connectionUrl) && Objects.equals(type, connection.type);
        }
        return false;
    }

    @Override
    public int hashCode() {
        return Objects.hash(host, port, connectionUrl, type);
    }

    @Override
    public String toString() {
        return JsonConverter.toJSON(this);
    }
}
