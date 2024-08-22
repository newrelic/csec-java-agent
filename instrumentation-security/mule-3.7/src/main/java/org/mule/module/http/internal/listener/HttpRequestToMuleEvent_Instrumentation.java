package org.mule.module.http.internal.listener;

import com.newrelic.agent.security.instrumentation.mule37.MuleHelper;
import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.instrumentation.helpers.LowSeverityHelper;
import com.newrelic.api.agent.security.instrumentation.helpers.ServletHelper;
import com.newrelic.api.agent.security.schema.AgentMetaData;
import com.newrelic.api.agent.security.schema.SecurityMetaData;
import com.newrelic.api.agent.security.schema.exceptions.NewRelicSecurityException;
import com.newrelic.api.agent.security.schema.operation.RXSSOperation;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
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
    public static MuleEvent transform(final HttpRequestContext requestContext, final MuleContext muleContext, final FlowConstruct flowConstruct, Boolean parseRequest, ListenerPath listenerPath) throws HttpRequestParsingException
    {
        boolean isLockAcquired = acquireLockIfPossible(requestContext.hashCode());
        MuleEvent event;
        MuleHelper.setRequestRoute(listenerPath);
        if (isLockAcquired) {
            preprocessSecurityHook(requestContext);
        }
        try {
            event = Weaver.callOriginal();
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
            securityRequest.setMethod(httpRequest.getMethod());
            securityRequest.setClientIP(requestContext.getClientConnection().getRemoteHostAddress().toString());
            securityRequest.setServerPort(
                    NewRelicSecurity
                            .getAgent()
                            .getSecurityMetaData()
                            .getCustomAttribute(MuleHelper.MULE_SERVER_PORT_ATTRIB_NAME, Integer.class)
            );

            if (securityRequest.getClientIP() != null && !securityRequest.getClientIP().trim().isEmpty()) {
                securityAgentMetaData.getIps().add(securityRequest.getClientIP());
                securityRequest.setClientPort(String.valueOf(requestContext.getClientConnection().getRemoteHostAddress().getPort()));
            }

            MuleHelper.processHttpRequestHeader(httpRequest, securityRequest);
            securityMetaData.setTracingHeaderValue(MuleHelper.getTraceHeader(securityRequest.getHeaders()));

            securityRequest.setProtocol(requestContext.getScheme());
            securityRequest.setUrl(httpRequest.getUri());

            // TODO: Create OutBoundHttp data here : Skipping for now.

            securityRequest.setContentType(MuleHelper.getContentType(httpRequest));

            // TODO: need to update UserClassEntity
            ServletHelper.registerUserLevelCode(MuleHelper.LIBRARY_NAME);
            securityRequest.setRequestParsed(true);
        } catch (Throwable ignored){
            NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.ERROR_GENERATING_HTTP_REQUEST, MuleHelper.MULE_3_7, ignored.getMessage()), ignored, HttpRequestToMuleEvent_Instrumentation.class.getName());
        }
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
                NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.SECURITY_EXCEPTION_MESSAGE, MuleHelper.MULE_3_7, e.getMessage()), e, HttpRequestToMuleEvent_Instrumentation.class.getName());
                throw e;
            }
            NewRelicSecurity.getAgent().log(LogLevel.SEVERE, String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, MuleHelper.MULE_3_7, e.getMessage()), e, HttpRequestToMuleEvent_Instrumentation.class.getName());
            NewRelicSecurity.getAgent().reportIncident(LogLevel.SEVERE , String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, MuleHelper.MULE_3_7, e.getMessage()), e, HttpRequestToMuleEvent_Instrumentation.class.getName());
        }
    }

    private static boolean acquireLockIfPossible(int hashcode) {
        try {
            return GenericHelper.acquireLockIfPossible(MuleHelper.getNrSecCustomAttribName(hashcode));
        } catch (Throwable ignored) {}
        return false;
    }

    private static void releaseLock(int hashcode) {
        try {
            GenericHelper.releaseLock(MuleHelper.getNrSecCustomAttribName(hashcode));
        } catch (Throwable e) {}
    }
}
