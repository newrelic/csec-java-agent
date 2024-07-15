package com.newrelic.agent.security.intcodeagent.utils;

import com.newrelic.agent.security.intcodeagent.models.javaagent.ExternalConnection;
import com.newrelic.agent.security.intcodeagent.models.javaagent.ExternalConnectionStats;
import com.newrelic.agent.security.intcodeagent.websocket.EventSendPool;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

public class ExternalConnectionsReporter {


    private final Set<ExternalConnection> externalConnections = ConcurrentHashMap.newKeySet();

    private ExternalConnectionsReporter() {}

    public static ExternalConnectionsReporter getInstance() {
        return InstanceHolder.INSTANCE;
    }

    private static final class InstanceHolder {
        private static final ExternalConnectionsReporter INSTANCE = new ExternalConnectionsReporter();
    }

    public boolean addExternalConnection(ExternalConnection externalConnection) {
        return externalConnections.add(externalConnection);
    }

    public void clearExternalConnections() {
        externalConnections.clear();
    }

    public void reportExternalConnections() {
        EventSendPool.getInstance().sendEvent(new ExternalConnectionStats(externalConnections));
        clearExternalConnections();
    }


}
