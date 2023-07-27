package com.newrelic.agent.security.intcodeagent.models.javaagent;

import com.newrelic.agent.security.intcodeagent.websocket.JsonConverter;

public class ThreadPoolStats {

    private Integer dispatcherQueueSize;

    private Integer eventSendQueueSize;

    public ThreadPoolStats() {
    }

    public ThreadPoolStats(Integer dispatcherQueueSize, Integer eventSendQueueSize) {
        this.dispatcherQueueSize = dispatcherQueueSize;
        this.eventSendQueueSize = eventSendQueueSize;
    }

    public ThreadPoolStats(ThreadPoolStats threadPoolStats) {
        this.dispatcherQueueSize = threadPoolStats.dispatcherQueueSize;
        this.eventSendQueueSize = threadPoolStats.eventSendQueueSize;
    }

    public Integer getDispatcherQueueSize() {
        return dispatcherQueueSize;
    }

    public void setDispatcherQueueSize(Integer dispatcherQueueSize) {
        this.dispatcherQueueSize = dispatcherQueueSize;
    }

    public Integer getEventSendQueueSize() {
        return eventSendQueueSize;
    }

    public void setEventSendQueueSize(Integer eventSendQueueSize) {
        this.eventSendQueueSize = eventSendQueueSize;
    }


    public String toString() {
        return JsonConverter.toJSON(this);
    }
}
