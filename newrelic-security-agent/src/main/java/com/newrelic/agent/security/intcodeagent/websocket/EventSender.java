package com.newrelic.agent.security.intcodeagent.websocket;

import com.newrelic.agent.security.intcodeagent.models.javaagent.JavaAgentEventBean;

import java.util.concurrent.Callable;

/**
 * Task to send events
 */
public class EventSender implements Callable<Boolean> {

    private Object event;

    public EventSender(String event) {
        this.event = event;
    }

    public EventSender(JavaAgentEventBean event) {
        this.event = event;
    }

    public Object getEvent() {
        return event;
    }

    public EventSender(Object event) {
        this.event = event;
    }

    /**
     * Utility thread to carry and send event one by one.
     *
     * @return
     * @throws Exception
     */
    @Override
    public Boolean call() throws Exception {
        if (event instanceof JavaAgentEventBean) {
            ((JavaAgentEventBean) event).setEventGenerationTime(System.currentTimeMillis());
        }
        if(WSUtils.isConnected()) {
            WSClient.getInstance().send(JsonConverter.toJSON(event));
        }
        return true;
    }

}
