package com.newrelic.api.agent.security.schema;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class AppServerInfo {

    String applicationDirectory;

    String serverBaseDirectory;

    String sameSiteCookies;

    String applicationTmpDirectory;

    Map<Integer, ServerConnectionConfiguration> connectionConfiguration;

    public AppServerInfo() {
        connectionConfiguration = new ConcurrentHashMap<>();
    }

    public String getApplicationDirectory() {
        return applicationDirectory;
    }

    public void setApplicationDirectory(String applicationDirectory) {
        this.applicationDirectory = applicationDirectory;
    }

    public String getServerBaseDirectory() {
        return serverBaseDirectory;
    }

    public void setServerBaseDirectory(String serverBaseDirectory) {
        this.serverBaseDirectory = serverBaseDirectory;
    }

    public String getSameSiteCookies() {
        return sameSiteCookies;
    }

    public void setSameSiteCookies(String sameSiteCookies) {
        this.sameSiteCookies = sameSiteCookies;
    }

    public String getApplicationTmpDirectory() {
        return applicationTmpDirectory;
    }

    public void setApplicationTmpDirectory(String applicationTmpDirectory) {
        this.applicationTmpDirectory = applicationTmpDirectory;
    }

    public Map<Integer, ServerConnectionConfiguration> getConnectionConfiguration() {
        return connectionConfiguration;
    }
}
