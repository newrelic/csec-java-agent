package com.newrelic.agent.security.intcodeagent.websocket;

import com.newrelic.agent.security.intcodeagent.apache.httpclient.SecurityClient;
import com.newrelic.agent.security.intcodeagent.communication.ConnectionFactory;
import com.newrelic.agent.security.intcodeagent.models.javaagent.JavaAgentEventBean;
import com.newrelic.api.agent.security.utils.SecurityConnection;
import org.json.simple.JSONStreamAware;

import java.util.concurrent.Callable;

/**
 * Task to send events
 */
public class EventSender implements Callable<Boolean> {

    private Object event;

    private String api;

    public EventSender(String event) {
        this.event = event;
    }

    public EventSender(JavaAgentEventBean event) {
        this.event = event;
    }

    public Object getEvent() {
        return event;
    }

    public EventSender(Object event, String api) {
        this.event = event;
        this.api = api;
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
        ConnectionFactory.getInstance().getSecurityConnection().send(event, api);
        return true;
    }

}
