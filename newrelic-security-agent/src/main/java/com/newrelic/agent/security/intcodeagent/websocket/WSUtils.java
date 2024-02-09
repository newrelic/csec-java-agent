package com.newrelic.agent.security.intcodeagent.websocket;

import com.newrelic.agent.security.AgentInfo;

import java.util.concurrent.atomic.AtomicBoolean;

public class WSUtils {

    private boolean isConnected = false;
    private AtomicBoolean isReconnecting = new AtomicBoolean(false);

    private WSUtils() {
    }

    private static final class InstanceHolder {
        static final WSUtils instance = new WSUtils();
    }

    public static WSUtils getInstance() {
        return InstanceHolder.instance;
    }


    void setConnected(boolean connected) {
        isConnected = connected;
        AgentInfo.getInstance().agentStatTrigger(false);
    }

    public static boolean isConnected() {
        if (InstanceHolder.instance != null) {
            return InstanceHolder.instance.isConnected;
        }
        return false;
    }

    public boolean isReconnecting() {
        return isReconnecting.get();
    }

    public void setReconnecting(boolean isReconnecting) {
        this.isReconnecting.set(isReconnecting);
    }

}
