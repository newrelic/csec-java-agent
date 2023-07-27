package com.newrelic.agent.security.intcodeagent.websocket;

import com.newrelic.agent.security.AgentInfo;

import java.util.concurrent.atomic.AtomicBoolean;

public class WSUtils {
    public static final String NEXT_WS_CONNECTION_ATTEMPT_WILL_BE_IN_S_SECONDS = "Next WS connection attempt will be in %s seconds";
    private static WSUtils instance;
    private static final Object lock = new Object();

    private boolean isConnected = false;
    private AtomicBoolean isReconnecting = new AtomicBoolean(false);

    private WSUtils() {
    }

    public static WSUtils getInstance() {
        if (instance == null) {
            synchronized (lock) {
                if (instance == null) {
                    instance = new WSUtils();
                }
            }
        }
        return instance;
    }


    void setConnected(boolean connected) {
        isConnected = connected;
        AgentInfo.getInstance().agentStatTrigger();
    }

    public static boolean isConnected() {
        if (instance != null) {
            return instance.isConnected;
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
