package com.newrelic.api.agent.security.instrumentation.helpers;

import com.newrelic.api.agent.security.schema.AppServerInfo;

public class AppServerInfoHelper {

    private static AppServerInfo appServerInfo = new AppServerInfo();

    public static AppServerInfo getAppServerInfo() {
        return appServerInfo;
    }
}
