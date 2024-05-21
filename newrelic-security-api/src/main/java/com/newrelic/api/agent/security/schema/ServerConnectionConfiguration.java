package com.newrelic.api.agent.security.schema;

public class ServerConnectionConfiguration {

    private Integer port;

    private String protocol;

    private boolean confirmed;

    private String endpoint;

    public ServerConnectionConfiguration() {
        this.confirmed = false;
    }

    public ServerConnectionConfiguration(int port, String scheme) {
        this.port = port;
        this.protocol = scheme;
        this.confirmed = false;
    }

    public Integer getPort() {
        return port;
    }

    public void setPort(Integer port) {
        this.port = port;
    }

    public String getProtocol() {
        return protocol;
    }

    public void setProtocol(String protocol) {
        this.protocol = protocol;
    }

    public boolean isConfirmed() {
        return confirmed;
    }

    public void setConfirmed(boolean confirmed) {
        this.confirmed = confirmed;
    }

    public String getEndpoint() {
        return endpoint;
    }

    public void setEndpoint(String endpoint) {
        this.endpoint = endpoint;
    }
}
