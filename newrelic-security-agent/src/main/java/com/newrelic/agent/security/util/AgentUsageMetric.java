package com.newrelic.agent.security.util;

import com.newrelic.agent.security.intcodeagent.websocket.EventSendPool;

public class AgentUsageMetric {

    public static Boolean isRASPProcessingActive() {
        if(EventSendPool.getInstance().getExecutor().getQueue().size() >
                EventSendPool.getInstance().getExecutor().getMaximumPoolSize()/2){
            return false;
        }
        return true;
    }

    public static Boolean isIASTRequestProcessingActive() {
        if(EventSendPool.getInstance().getExecutor().getQueue().size() >
                EventSendPool.getInstance().getExecutor().getMaximumPoolSize()*2/3){
            return false;
        }
        return true;
    }


}
