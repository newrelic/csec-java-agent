package com.sun.net.httpserver;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.LowSeverityHelper;
import com.newrelic.api.agent.security.instrumentation.helpers.ServletHelper;
import com.newrelic.api.agent.security.schema.AgentMetaData;
import com.newrelic.api.agent.security.schema.HttpRequest;
import com.newrelic.api.agent.security.schema.SecurityMetaData;
import com.newrelic.api.agent.security.schema.exceptions.NewRelicSecurityException;
import com.newrelic.api.agent.security.schema.operation.RXSSOperation;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;

import java.io.IOException;
import java.util.Arrays;

@Weave(originalName = "com.sun.net.httpserver.Filter", type = MatchType.BaseClass)
public class Filter_Instrumentation {
    public void doFilter (HttpExchange exchange, Filter.Chain chain) throws IOException {
        boolean isServletLockAcquired = acquireServletLockIfPossible();

        if (isServletLockAcquired){
            preprocessSecurityHook(exchange);
        }
        try{
            Weaver.callOriginal();
        } finally {
            if (isServletLockAcquired){
                releaseServletLock();
            }
        }
        if (isServletLockAcquired){
            postProcessSecurityHook(exchange);
        }
    }

    private void preprocessSecurityHook(HttpExchange exchange) {
        try {
            if (!NewRelicSecurity.isHookProcessingActive()) {
                return;
            }
            SecurityMetaData securityMetaData = NewRelicSecurity.getAgent().getSecurityMetaData();

            HttpRequest securityRequest = securityMetaData.getRequest();
            if (securityRequest.isRequestParsed()) {
                return;
            }

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

            securityRequest.setContentType(HttpServerHelper.getContentType(exchange.getRequestHeaders()));
            ServletHelper.registerUserLevelCode("sun-net-http-server");
            securityRequest.setRequestParsed(true);
        } catch (Throwable ignored){}
    }
    private void postProcessSecurityHook(HttpExchange exchange) {
        try {
            if (!NewRelicSecurity.isHookProcessingActive()) {
                return;
            }
            //Add request URI hash to low severity event filter
            LowSeverityHelper.addRrequestUriToEventFilter(NewRelicSecurity.getAgent().getSecurityMetaData().getRequest());

            RXSSOperation rxssOperation = new RXSSOperation(NewRelicSecurity.getAgent().getSecurityMetaData().getRequest(),
                    NewRelicSecurity.getAgent().getSecurityMetaData().getResponse(),
                    this.getClass().getName(), HttpServerHelper.HANDLE_METHOD_NAME);
            NewRelicSecurity.getAgent().registerOperation(rxssOperation);
            ServletHelper.tmpFileCleanUp(NewRelicSecurity.getAgent().getSecurityMetaData().getFuzzRequestIdentifier().getTempFiles());
        } catch (Throwable e) {
            if(e instanceof NewRelicSecurityException){
                e.printStackTrace();
                throw e;
            }
        }
    }

    private boolean acquireServletLockIfPossible() {
        try {
            return HttpServerHelper.acquireServletLockIfPossible();
        } catch (Throwable ignored) {}
        return false;
    }
    private void releaseServletLock() {
        try {
            HttpServerHelper.releaseServletLock();
        } catch (Throwable ignored) {}
    }

}
