package org.mule.module.http.internal.listener.async;

import com.newrelic.agent.security.instrumentation.mule36.MuleHelper;
import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.instrumentation.helpers.LowSeverityHelper;
import com.newrelic.api.agent.security.instrumentation.helpers.ServletHelper;
import com.newrelic.api.agent.security.schema.AgentMetaData;
import com.newrelic.api.agent.security.schema.SecurityMetaData;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.security.schema.exceptions.NewRelicSecurityException;
import com.newrelic.api.agent.security.schema.operation.RXSSOperation;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import org.mule.module.http.internal.domain.request.HttpRequest;
import org.mule.module.http.internal.domain.request.HttpRequestContext;

@Weave(type = MatchType.Interface, originalName = "org.mule.module.http.internal.listener.async.RequestHandler")
public class RequestHandler_Instrumentation {
    public void handleRequest(HttpRequestContext requestContext, HttpResponseReadyCallback responseCallback) {
        boolean isLockAcquired = acquireLockIfPossible(requestContext.hashCode());
        if (isLockAcquired) {
            preprocessSecurityHook(requestContext);
        }
        try {
            Weaver.callOriginal();
        } finally {
            if (isLockAcquired) {
                releaseLock(requestContext.hashCode());
            }
        }
        if (isLockAcquired) {
            postProcessSecurityHook();
        }
    }

    private void preprocessSecurityHook(HttpRequestContext requestContext) {
        try {
            SecurityMetaData securityMetaData = NewRelicSecurity.getAgent().getSecurityMetaData();
            com.newrelic.api.agent.security.schema.HttpRequest securityRequest = securityMetaData.getRequest();

            AgentMetaData securityAgentMetaData = securityMetaData.getMetaData();

            HttpRequest httpRequest = requestContext.getRequest();

            if (httpRequest.getEntity() != null) {
                MuleHelper.registerStreamHashIfNeeded(httpRequest.getEntity().hashCode(), MuleHelper.REQUEST_ENTITY_STREAM);
            }
            securityRequest.setMethod(httpRequest.getMethod());
            securityRequest.setClientIP(requestContext.getRemoteHostAddress().toString());
            if (NewRelicSecurity.getAgent().getSecurityMetaData().getCustomAttribute(MuleHelper.MULE_SERVER_PORT_ATTRIB_NAME, Integer.class) != null) {
                securityRequest.setServerPort(NewRelicSecurity.getAgent().getSecurityMetaData().getCustomAttribute(MuleHelper.MULE_SERVER_PORT_ATTRIB_NAME, Integer.class));
            }

            if (securityRequest.getClientIP() != null && !securityRequest.getClientIP().trim().isEmpty()) {
                securityAgentMetaData.getIps().add(securityRequest.getClientIP());
                securityRequest.setClientPort(String.valueOf(requestContext.getRemoteHostAddress().getPort()));
            }

            MuleHelper.processHttpRequestHeader(httpRequest, securityRequest);
            securityMetaData.setTracingHeaderValue(MuleHelper.getTraceHeader(securityRequest.getHeaders()));

            securityRequest.setProtocol(requestContext.getScheme());
            securityRequest.setUrl(httpRequest.getUri());

            // TODO: Create OutBoundHttp data here : Skipping for now.

            securityRequest.setContentType(MuleHelper.getContentType(securityRequest.getHeaders()));
            securityRequest.setRequestParsed(true);
        } catch (Throwable ignored){}
    }

    private void postProcessSecurityHook() {
        try {
            if (!NewRelicSecurity.isHookProcessingActive()) {
                return;
            }
            ServletHelper.registerUserLevelCode(MuleHelper.LIBRARY_NAME);
//            ServletHelper.executeBeforeExitingTransaction();
            //Add request URI hash to low severity event filter
            LowSeverityHelper.addRrequestUriToEventFilter(NewRelicSecurity.getAgent().getSecurityMetaData().getRequest());

            if(!ServletHelper.isResponseContentTypeExcluded(NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().getResponseContentType())) {
                RXSSOperation rxssOperation = new RXSSOperation(
                        NewRelicSecurity.getAgent().getSecurityMetaData().getRequest(),
                        NewRelicSecurity.getAgent().getSecurityMetaData().getResponse(),
                        this.getClass().getName(),
                        MuleHelper.HANDLE_REQUEST_METHOD
                );
                NewRelicSecurity.getAgent().registerOperation(rxssOperation);
            }
            ServletHelper.tmpFileCleanUp(NewRelicSecurity.getAgent().getSecurityMetaData().getFuzzRequestIdentifier().getTempFiles());
        } catch (Throwable e) {
            if(e instanceof NewRelicSecurityException){
                NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.SECURITY_EXCEPTION_MESSAGE, MuleHelper.MULE_36, e.getMessage()), e, this.getClass().getName());
                throw e;
            }
        }
    }

    private boolean acquireLockIfPossible(int hashcode) {
        return GenericHelper.acquireLockIfPossible(VulnerabilityCaseType.REFLECTED_XSS, MuleHelper.getNrSecCustomAttribName());
    }

    private void releaseLock(int hashcode) {
        GenericHelper.releaseLock(MuleHelper.getNrSecCustomAttribName());
    }
}
