package org.mule.module.http.internal.listener;

import com.newrelic.agent.security.instrumentation.mule36.MuleHelper;
import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.instrumentation.helpers.LowSeverityHelper;
import com.newrelic.api.agent.security.instrumentation.helpers.ServletHelper;
import com.newrelic.api.agent.security.schema.AgentMetaData;
import com.newrelic.api.agent.security.schema.SecurityMetaData;
import com.newrelic.api.agent.security.schema.exceptions.NewRelicSecurityException;
import com.newrelic.api.agent.security.schema.operation.RXSSOperation;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import org.mule.api.MuleContext;
import org.mule.api.MuleEvent;
import org.mule.api.construct.FlowConstruct;
import org.mule.module.http.internal.domain.request.HttpRequest;
import org.mule.module.http.internal.domain.request.HttpRequestContext;

@Weave(type = MatchType.ExactClass, originalName = "org.mule.module.http.internal.listener.HttpRequestToMuleEvent")
public class HttpRequestToMuleEvent_Instrumentation {
    public static MuleEvent transform(final HttpRequestContext requestContext, final MuleContext muleContext, final FlowConstruct flowConstruct, Boolean parseRequest, String listenerPath) throws HttpRequestParsingException
    {
        boolean isLockAcquired = acquireLockIfPossible(requestContext.hashCode());
        MuleEvent event;
        if (isLockAcquired) {
            preprocessSecurityHook(requestContext);
        }
        try {
            event = Weaver.callOriginal();
            if (NewRelicSecurity.isHookProcessingActive()) {
                NewRelicSecurity.getAgent().getSecurityMetaData().addCustomAttribute(MuleHelper.MULE_ENCODING, event.getEncoding());
            }
        } finally {
            if (isLockAcquired) {
                releaseLock(requestContext.hashCode());
            }
        }
        if (isLockAcquired) {
            postProcessSecurityHook();
        }
        return event;
    }

    private static void preprocessSecurityHook(HttpRequestContext requestContext) {
        try {
            if (!NewRelicSecurity.isHookProcessingActive()) {
                return;
            }
            SecurityMetaData securityMetaData = NewRelicSecurity.getAgent().getSecurityMetaData();

            com.newrelic.api.agent.security.schema.HttpRequest securityRequest = securityMetaData.getRequest();
            if (securityRequest.isRequestParsed()) {
                return;
            }

            AgentMetaData securityAgentMetaData = securityMetaData.getMetaData();

            HttpRequest httpRequest = requestContext.getRequest();
            if (httpRequest.getEntity() != null) {
                securityMetaData.addCustomAttribute(MuleHelper.getNrSecCustomAttribName(MuleHelper.REQUEST_ENTITY_STREAM), httpRequest.getEntity().hashCode());
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

            // TODO: need to update UserClassEntity
            ServletHelper.registerUserLevelCode(MuleHelper.LIBRARY_NAME);
            securityRequest.setRequestParsed(true);
        } catch (Throwable ignored){}
    }

    private static void postProcessSecurityHook() {
        try {
            if (!NewRelicSecurity.isHookProcessingActive()
            ) {
                return;
            }
            ServletHelper.executeBeforeExitingTransaction();
            //Add request URI hash to low severity event filter
            LowSeverityHelper.addRrequestUriToEventFilter(NewRelicSecurity.getAgent().getSecurityMetaData().getRequest());

            if(!ServletHelper.isResponseContentTypeExcluded(NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().getResponseContentType())) {
                RXSSOperation rxssOperation = new RXSSOperation(
                        NewRelicSecurity.getAgent().getSecurityMetaData().getRequest(),
                        NewRelicSecurity.getAgent().getSecurityMetaData().getResponse(),
                        HttpRequestToMuleEvent_Instrumentation.class.getName(),
                        MuleHelper.TRANSFORM_METHOD
                );
                NewRelicSecurity.getAgent().registerOperation(rxssOperation);
            }
            ServletHelper.tmpFileCleanUp(NewRelicSecurity.getAgent().getSecurityMetaData().getFuzzRequestIdentifier().getTempFiles());
        } catch (Throwable e) {
            if(e instanceof NewRelicSecurityException){
                e.printStackTrace();
                throw e;
            }
        }
    }

    private static boolean acquireLockIfPossible(int hashcode) {
        try {
            return GenericHelper.acquireLockIfPossible(MuleHelper.getNrSecCustomAttribName());
        } catch (Throwable ignored) {}
        return false;
    }

    private static void releaseLock(int hashcode) {
        try {
            GenericHelper.releaseLock(MuleHelper.getNrSecCustomAttribName());
        } catch (Throwable e) {}
    }
}
