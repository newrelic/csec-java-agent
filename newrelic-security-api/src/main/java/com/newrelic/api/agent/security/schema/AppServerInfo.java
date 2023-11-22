package com.newrelic.api.agent.security.schema;

public class AppServerInfo {

    String applicationDirectory;

    String serverBaseDirectory;

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
}
