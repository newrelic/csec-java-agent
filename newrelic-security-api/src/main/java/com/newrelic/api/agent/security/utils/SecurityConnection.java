package com.newrelic.api.agent.security.utils;

import com.newrelic.api.agent.security.schema.http.ReadResult;

public interface SecurityConnection {

    void setConnected(boolean connected);

    boolean isConnected();

    boolean isReconnecting();

    void setReconnecting(boolean isReconnecting);

    ReadResult send(Object message, String api) throws ConnectionException;

    void close(String message);

    void ping();

    void reconnectIfRequired();
}
