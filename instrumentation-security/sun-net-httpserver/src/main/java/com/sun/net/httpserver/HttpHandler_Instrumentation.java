package com.sun.net.httpserver;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.instrumentation.helpers.LowSeverityHelper;
import com.newrelic.api.agent.security.instrumentation.helpers.ServletHelper;
import com.newrelic.api.agent.security.schema.AgentMetaData;
import com.newrelic.api.agent.security.schema.HttpRequest;
import com.newrelic.api.agent.security.schema.HttpResponse;
import com.newrelic.api.agent.security.schema.SecurityMetaData;
import com.newrelic.api.agent.security.schema.exceptions.NewRelicSecurityException;
import com.newrelic.api.agent.security.schema.operation.RXSSOperation;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;

import java.io.IOException;

@Weave(originalName = "com.sun.net.httpserver.HttpHandler", type = MatchType.Interface)
public class HttpHandler_Instrumentation {
    public void handle (HttpExchange exchange) throws IOException {
        boolean isServletLockAcquired = HttpServerHelper.acquireServletLockIfPossible();

        if (isServletLockAcquired){
            preprocessSecurityHook(exchange);
        }
        ServletHelper.registerUserLevelCode(HttpServerHelper.SUN_NET_HTTP_SERVER);
        HttpServerHelper.detectRoute();
        try{
            Weaver.callOriginal();
        } finally {
            if (isServletLockAcquired){
                HttpServerHelper.releaseServletLock();
            }
        }
        if (isServletLockAcquired){
            postProcessSecurityHook(exchange);
        }
    }

    private void preprocessSecurityHook(HttpExchange exchange) {
        try {
            SecurityMetaData securityMetaData = NewRelicSecurity.getAgent().getSecurityMetaData();
            HttpRequest securityRequest = securityMetaData.getRequest();


            AgentMetaData securityAgentMetaData = securityMetaData.getMetaData();
            securityRequest.setMethod(exchange.getRequestMethod());
            securityRequest.setClientIP(exchange.getRemoteAddress().getAddress().getHostAddress());
            securityRequest.setServerPort(exchange.getLocalAddress().getPort());

            if (securityRequest.getClientIP() != null && !securityRequest.getClientIP().trim().isEmpty()) {
                securityAgentMetaData.getIps().add(securityRequest.getClientIP());
                securityRequest.setClientPort(String.valueOf(exchange.getRemoteAddress().getPort()));
            }

            HttpServerHelper.processHttpRequestHeaders(exchange.getRequestHeaders(), securityRequest);
            securityMetaData.setTracingHeaderValue(HttpServerHelper.getTraceHeader(securityRequest.getHeaders()));
            securityRequest.setProtocol(HttpServerHelper.getProtocol(exchange));
            securityRequest.setUrl(String.valueOf(exchange.getRequestURI()));

            String queryString = exchange.getRequestURI().getQuery();
            if (queryString != null && !queryString.trim().isEmpty()) {
                securityRequest.setUrl(securityRequest.getUrl() + HttpServerHelper.QUESTION_MARK + queryString);
            }

            securityRequest.setContentType(HttpServerHelper.getContentType(securityRequest.getHeaders()));
            securityRequest.setRequestParsed(true);
        } catch (Throwable e){
            NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.ERROR_GENERATING_HTTP_REQUEST, HttpServerHelper.SUN_NET_HTTPSERVER, e.getMessage()), e, this.getClass().getName());
        }
    }
    private void postProcessSecurityHook(HttpExchange exchange) {
        try {
            if(!NewRelicSecurity.isHookProcessingActive() || NewRelicSecurity.getAgent().getIastDetectionCategory().getRxssEnabled()){
                return;
            }
            HttpResponse securityResponse = NewRelicSecurity.getAgent().getSecurityMetaData().getResponse();
            securityResponse.setStatusCode(exchange.getResponseCode());
            HttpServerHelper.processHttpResponseHeaders(exchange.getResponseHeaders(), securityResponse);
            securityResponse.setContentType(HttpServerHelper.getContentType(securityResponse.getHeaders()));

//            ServletHelper.executeBeforeExitingTransaction();
            //Add request URI hash to low severity event filter
            LowSeverityHelper.addRrequestUriToEventFilter(NewRelicSecurity.getAgent().getSecurityMetaData().getRequest());

            if(!ServletHelper.isResponseContentTypeExcluded(NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().getResponseContentType())) {
                RXSSOperation rxssOperation = new RXSSOperation(NewRelicSecurity.getAgent().getSecurityMetaData().getRequest(),
                        NewRelicSecurity.getAgent().getSecurityMetaData().getResponse(),
                        this.getClass().getName(), HttpServerHelper.HANDLE_METHOD_NAME);
                NewRelicSecurity.getAgent().registerOperation(rxssOperation);
            }
            ServletHelper.tmpFileCleanUp(NewRelicSecurity.getAgent().getSecurityMetaData().getFuzzRequestIdentifier().getTempFiles());
        } catch (Throwable e) {
            if (e instanceof NewRelicSecurityException) {
                NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.SECURITY_EXCEPTION_MESSAGE, HttpServerHelper.SUN_NET_HTTPSERVER, e.getMessage()), e, this.getClass().getName());
                throw e;
            }
            NewRelicSecurity.getAgent().log(LogLevel.SEVERE, String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, HttpServerHelper.SUN_NET_HTTPSERVER, e.getMessage()), e, this.getClass().getName());
            NewRelicSecurity.getAgent().reportIncident(LogLevel.SEVERE, String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, HttpServerHelper.SUN_NET_HTTPSERVER, e.getMessage()), e, this.getClass().getName());
        }
    }
}
