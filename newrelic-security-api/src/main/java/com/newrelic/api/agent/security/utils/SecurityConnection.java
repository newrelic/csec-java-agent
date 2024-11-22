package com.newrelic.api.agent.security.utils;

import com.newrelic.api.agent.security.schema.http.ReadResult;

public interface SecurityConnection {

    public void setConnected(boolean connected);

    public boolean isConnected();

    public boolean isReconnecting();

    public void setReconnecting(boolean isReconnecting);

    public ReadResult send(Object message, String api) throws ConnectionException;

    public void close(String message);

    public void ping();
}
