package com.newrelic.agent.security.intcodeagent.utils;

import com.newrelic.agent.security.intcodeagent.logging.IAgentConstants;
import com.newrelic.agent.security.intcodeagent.models.javaagent.HttpResponseEvent;
import com.newrelic.agent.security.intcodeagent.websocket.EventSendPool;
import com.newrelic.api.agent.NewRelic;
import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.schema.SecurityMetaData;
import com.newrelic.api.agent.security.schema.operation.SecureCookieOperationSet;
import org.apache.commons.lang3.StringUtils;

public class TransactionUtils {

    public static void reportHttpResponse() {
        if(!NewRelicSecurity.isHookProcessingActive()) {
            return;
        }
        if(NewRelic.getAgent().getTransaction().isWebTransaction()) {
            SecurityMetaData securityMetaData = NewRelicSecurity.getAgent().getSecurityMetaData();
            if(securityMetaData != null
                    && securityMetaData.getFuzzRequestIdentifier().getK2Request()
                    && StringUtils.equals(securityMetaData.getFuzzRequestIdentifier().getNextStage().getStatus(), IAgentConstants.VULNERABLE)
                    && !securityMetaData.getResponse().isEmpty()) {
                HttpResponseEvent httpResponseEvent = new HttpResponseEvent(NewRelicSecurity.getAgent().getSecurityMetaData().getResponse(), true);
                if(!httpResponseEvent.isEmpty()) {
                    EventSendPool.getInstance().sendEvent(httpResponseEvent);
                }
            }
        }
    }

    public static void executeBeforeExitingTransaction() {
        Boolean exitLogicPerformed = NewRelicSecurity.getAgent().getSecurityMetaData().getCustomAttribute("EXIT_RECORDED", Boolean.class);
        if(Boolean.TRUE.equals(exitLogicPerformed) || !NewRelicSecurity.isHookProcessingActive()){
            return;
        }

        int responseCode = NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().getStatusCode();
        if(responseCode >= 500){
            Exception exception = NewRelicSecurity.getAgent().getSecurityMetaData().getCustomAttribute("ENDMOST_EXCEPTION", Exception.class);
            NewRelicSecurity.getAgent().recordExceptions(NewRelicSecurity.getAgent().getSecurityMetaData(), exception);
        }

        SecureCookieOperationSet operations = NewRelicSecurity.getAgent().getSecurityMetaData().getCustomAttribute("SECURE_COOKIE_OPERATION", SecureCookieOperationSet.class);
        if(operations != null) {
            NewRelicSecurity.getAgent().registerOperation(operations);
            NewRelicSecurity.getAgent().getSecurityMetaData().addCustomAttribute("SECURE_COOKIE_OPERATION", null);
        }
        NewRelicSecurity.getAgent().getSecurityMetaData().addCustomAttribute("EXIT_RECORDED", true);
    }
}
