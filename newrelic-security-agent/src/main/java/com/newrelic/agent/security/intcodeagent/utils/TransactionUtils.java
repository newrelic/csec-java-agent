package com.newrelic.agent.security.intcodeagent.utils;

import com.newrelic.agent.security.intcodeagent.communication.ConnectionFactory;
import com.newrelic.agent.security.intcodeagent.filelogging.FileLoggerThreadPool;
import com.newrelic.agent.security.intcodeagent.logging.IAgentConstants;
import com.newrelic.agent.security.intcodeagent.models.javaagent.HttpResponseEvent;
import com.newrelic.agent.security.intcodeagent.websocket.EventSendPool;
import com.newrelic.api.agent.NewRelic;
import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.schema.HttpResponse;
import com.newrelic.api.agent.security.schema.SecurityMetaData;
import com.newrelic.api.agent.security.schema.operation.SecureCookieOperationSet;
import com.newrelic.api.agent.security.utils.ConnectionException;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import org.apache.commons.lang3.StringUtils;

public class TransactionUtils {

    private static FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

    public static void reportHttpResponse() {
        if(!NewRelicSecurity.isHookProcessingActive()) {
            return;
        }
        if(NewRelic.getAgent().getTransaction().isWebTransaction()) {
            SecurityMetaData securityMetaData = NewRelicSecurity.getAgent().getSecurityMetaData();

            /* Send response event only when event is generated by phase 2 control command */
            if(securityMetaData != null
                    && securityMetaData.getFuzzRequestIdentifier().getK2Request()
                    && StringUtils.equals(securityMetaData.getFuzzRequestIdentifier().getNextStage().getStatus(), IAgentConstants.VULNERABLE)
                    && !securityMetaData.getResponse().isEmpty()) {
//                trimResponseBody(NewRelicSecurity.getAgent().getSecurityMetaData().getResponse());
                HttpResponseEvent httpResponseEvent = new HttpResponseEvent(NewRelicSecurity.getAgent().getSecurityMetaData().getResponse(), true);
                if(NewRelicSecurity.getAgent().getIastDetectionCategory().getRxssEnabled()){
                    httpResponseEvent.getHttpResponse().setBody(new StringBuilder(StringUtils.EMPTY));
                }
                if(!httpResponseEvent.isEmpty()) {
                    try {
                        ConnectionFactory.getInstance().getSecurityConnection().send(httpResponseEvent, "postAny");
                    } catch (ConnectionException e) {
                        logger.log(LogLevel.SEVERE, String.format("Error while sending response event message : %s, cause %s", e.getMessage(), e.getCause()), TransactionUtils.class.getName());
                        logger.log(LogLevel.FINEST, "Error while sending response event message", e, TransactionUtils.class.getName());
                    }
                }
            }
        }
    }

    public static boolean trimResponseBody(HttpResponse response) {
        if(response.getBody().getSb().length() > HttpResponse.MAX_ALLOWED_RESPONSE_BODY_LENGTH) {
            response.setBody(new StringBuilder(response.getBody().getSb().substring(0, HttpResponse.MAX_ALLOWED_RESPONSE_BODY_LENGTH)));
            response.setBody(new StringBuilder(response.getBody().append("...")));
            response.setDataTruncated(true);
            return true;
        }
        return false;
    }

    public static void executeBeforeExitingTransaction() {
        Boolean exitLogicPerformed = NewRelicSecurity.getAgent().getSecurityMetaData().getCustomAttribute("EXIT_RECORDED", Boolean.class);
        if(Boolean.TRUE.equals(exitLogicPerformed) || !NewRelicSecurity.isHookProcessingActive()){
            return;
        }

        int responseCode = NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().getStatusCode();
        if(responseCode >= 500  && !StringUtils.equals(NewRelicSecurity.getSecurityMode(), "IAST_MONITORING")){
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
