package com.newrelic.api.agent.security.schema;

public class AppServerInfo {

    String applicationDirectory;

    String serverBaseDirectory;

    String sameSiteCookies;

    String applicationTmpDirectory;

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
}
