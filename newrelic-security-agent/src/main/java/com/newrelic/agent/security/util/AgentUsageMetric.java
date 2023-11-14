package com.newrelic.agent.security.util;

import com.newrelic.agent.security.instrumentator.dispatcher.DispatcherPool;
import com.newrelic.agent.security.intcodeagent.websocket.EventSendPool;

public class AgentUsageMetric {

    public static Boolean isRASPProcessingActive() {
        if(EventSendPool.getInstance().getExecutor().getQueue().size() >
                EventSendPool.getInstance().getMaxQueueSize()/2){
            return false;
        }
        if(DispatcherPool.getInstance().getExecutor().getQueue().size() >
                DispatcherPool.getInstance().getMaxQueueSize()*2/3){
            return false;
        }
        return true;
    }

    public static Boolean isIASTRequestProcessingActive() {
        if(EventSendPool.getInstance().getExecutor().getQueue().size() >
                EventSendPool.getInstance().getExecutor().getMaximumPoolSize()*2/3){
            return false;
        }
        if(DispatcherPool.getInstance().getExecutor().getQueue().size() >
                DispatcherPool.getInstance().getExecutor().getMaximumPoolSize()*0.75){
            return false;
        }
        return true;
    }


}
