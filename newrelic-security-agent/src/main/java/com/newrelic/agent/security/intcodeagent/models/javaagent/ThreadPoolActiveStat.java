package com.newrelic.agent.security.intcodeagent.models.javaagent;

import com.newrelic.agent.security.intcodeagent.websocket.JsonConverter;

public class ThreadPoolActiveStat {

    private Integer activeThreadCount;

    private Integer currentQueueSize;

    public ThreadPoolActiveStat(Integer activeThreadCount, Integer currentQueueSize) {
        this.activeThreadCount = activeThreadCount;
        this.currentQueueSize = currentQueueSize;
    }

    public Integer getActiveThreadCount() {
        return activeThreadCount;
    }

    public Integer getCurrentQueueSize() {
        return currentQueueSize;
    }

    public String toString() {
        return JsonConverter.toJSON(this);
    }
}
