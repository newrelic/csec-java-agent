package com.newrelic.agent.security.intcodeagent.models.javaagent;

import com.newrelic.agent.security.intcodeagent.websocket.JsonConverter;

import java.util.concurrent.atomic.AtomicInteger;

public class WebSocketConnectionStats {

    private AtomicInteger messagesSent = new AtomicInteger();

    private AtomicInteger messagesReceived = new AtomicInteger();

    private AtomicInteger connectionReconnected = new AtomicInteger();

    private AtomicInteger connectionFailure = new AtomicInteger();

    private AtomicInteger receivedReconnectAtWill = new AtomicInteger();

    private AtomicInteger sendFailure = new AtomicInteger();

    public WebSocketConnectionStats() {
    }

    public WebSocketConnectionStats(WebSocketConnectionStats stats) {
        messagesSent.set(stats.messagesSent.get());
        messagesReceived.set(stats.messagesReceived.get());
        connectionReconnected.set(stats.connectionReconnected.get());
        connectionFailure.set(stats.connectionFailure.get());
        receivedReconnectAtWill.set(stats.receivedReconnectAtWill.get());
        sendFailure.set(stats.sendFailure.get());
    }

    public AtomicInteger getMessagesSent() {
        return messagesSent;
    }

    public AtomicInteger getMessagesReceived() {
        return messagesReceived;
    }

    public AtomicInteger getConnectionReconnected() {
        return connectionReconnected;
    }

    public AtomicInteger getConnectionFailure() {
        return connectionFailure;
    }

    public AtomicInteger getReceivedReconnectAtWill() {
        return receivedReconnectAtWill;
    }

    public AtomicInteger getSendFailure() {
        return sendFailure;
    }

    public int incrementMessagesSent() {
        return messagesSent.incrementAndGet();
    }

    public int incrementMessagesReceived() {
        return messagesReceived.incrementAndGet();
    }

    public int incrementConnectionReconnected() {
        return connectionReconnected.incrementAndGet();
    }

    public int incrementConnectionFailure() {
        return connectionFailure.incrementAndGet();
    }

    public int incrementReceivedReconnectAtWill() {
        return receivedReconnectAtWill.incrementAndGet();
    }

    public int incrementSendFailure() {
        return sendFailure.incrementAndGet();
    }

    public void reset() {
        messagesSent.set(0);
        messagesReceived.set(0);
        connectionReconnected.set(0);
        connectionFailure.set(0);
        receivedReconnectAtWill.set(0);
    }

    public String toString() {
        return JsonConverter.toJSON(this);
    }
}
