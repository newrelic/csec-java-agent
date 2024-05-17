package jakarta.servlet;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.instrumentation.helpers.LowSeverityHelper;
import com.newrelic.api.agent.security.instrumentation.helpers.ServletHelper;
import com.newrelic.api.agent.security.schema.AgentMetaData;
import com.newrelic.api.agent.security.schema.HttpRequest;
import com.newrelic.api.agent.security.schema.RequestCategory;
import com.newrelic.api.agent.security.schema.SecurityMetaData;
import com.newrelic.api.agent.security.schema.exceptions.NewRelicSecurityException;
import com.newrelic.api.agent.security.schema.operation.RXSSOperation;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import com.newrelic.agent.security.instrumentation.servlet6.HttpServletHelper;
import jakarta.servlet.http.HttpServletRequest;

import java.io.IOException;
import java.util.Arrays;

@Weave(type = MatchType.Interface, originalName = "jakarta.servlet.FilterChain")
public abstract class FilterChain_Instrumentation {

    public void doFilter(ServletRequest request, ServletResponse response) throws IOException, ServletException {
        boolean isServletLockAcquired = acquireServletLockIfPossible();
        if(isServletLockAcquired) {
            preprocessSecurityHook(request, response);
        }
        try {
            Weaver.callOriginal();
        } finally {
            if(isServletLockAcquired){
                releaseServletLock();
            }
        }
        if(isServletLockAcquired) {
            postProcessSecurityHook(request, response);
        }
    }

    private void preprocessSecurityHook(ServletRequest request, ServletResponse response) {
        try {
            if (!NewRelicSecurity.isHookProcessingActive()
                    || !(request instanceof HttpServletRequest)
            ) {
                return;
            }
            SecurityMetaData securityMetaData = NewRelicSecurity.getAgent().getSecurityMetaData();

            HttpRequest securityRequest = securityMetaData.getRequest();
            if (securityRequest.isRequestParsed()) {
                return;
            }

            AgentMetaData securityAgentMetaData = securityMetaData.getMetaData();

            HttpServletRequest httpServletRequest = (HttpServletRequest) request;
            securityRequest.setMethod(httpServletRequest.getMethod());
            securityRequest.setClientIP(httpServletRequest.getRemoteAddr());
            securityRequest.setServerPort(httpServletRequest.getLocalPort());

            if (securityRequest.getClientIP() != null && !securityRequest.getClientIP().trim().isEmpty()) {
                securityAgentMetaData.getIps().add(securityRequest.getClientIP());
                securityRequest.setClientPort(String.valueOf(httpServletRequest.getRemotePort()));
            }

            HttpServletHelper.processHttpRequestHeader(httpServletRequest, securityRequest);

            securityMetaData.setTracingHeaderValue(ServletHelper.getTraceHeader(securityRequest.getHeaders()));

            NewRelicSecurity.getAgent().setEmptyIastDataRequestEntry(ServletHelper.iastDataRequestAddEmptyEntry(securityMetaData.getFuzzRequestIdentifier(), securityMetaData.getTracingHeaderValue(), securityMetaData.getCustomAttribute(GenericHelper.CSEC_PARENT_ID, String.class)), RequestCategory.HTTP);

            securityRequest.setProtocol(httpServletRequest.getScheme());
            securityRequest.setUrl(httpServletRequest.getRequestURI());

            // TODO: Create OutBoundHttp data here : Skipping for now.

            String queryString = httpServletRequest.getQueryString();
            if (queryString != null && !queryString.trim().isEmpty()) {
                securityRequest.setUrl(securityRequest.getUrl() + HttpServletHelper.QUESTION_MARK + queryString);
            }
            securityRequest.setContentType(httpServletRequest.getContentType());


            StackTraceElement[] trace = Thread.currentThread().getStackTrace();
            securityMetaData.getMetaData().setServiceTrace(Arrays.copyOfRange(trace, 1, trace.length));
            securityRequest.setRequestParsed(true);
        } catch (Throwable e){
            NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.ERROR_GENERATING_HTTP_REQUEST, HttpServletHelper.SERVLET_6_0, e.getMessage()), e, this.getClass().getName());
        }
    }

    private void postProcessSecurityHook(ServletRequest request, ServletResponse response) {
        try {
            if (!NewRelicSecurity.isHookProcessingActive()
            ) {
                return;
            }
            //Add request URI hash to low severity event filter
            LowSeverityHelper.addRrequestUriToEventFilter(NewRelicSecurity.getAgent().getSecurityMetaData().getRequest());

            if(!ServletHelper.isResponseContentTypeExcluded(NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().getResponseContentType())) {
                RXSSOperation rxssOperation = new RXSSOperation(NewRelicSecurity.getAgent().getSecurityMetaData().getRequest(),
                        NewRelicSecurity.getAgent().getSecurityMetaData().getResponse(),
                        this.getClass().getName(), HttpServletHelper.SERVICE_METHOD_NAME);
                NewRelicSecurity.getAgent().registerOperation(rxssOperation);
            }
            ServletHelper.tmpFileCleanUp(NewRelicSecurity.getAgent().getSecurityMetaData().getFuzzRequestIdentifier().getTempFiles());
        } catch (Throwable e) {
            if (e instanceof NewRelicSecurityException) {
                NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.SECURITY_EXCEPTION_MESSAGE, HttpServletHelper.SERVLET_6_0, e.getMessage()), e, FilterChain_Instrumentation.class.getName());
                throw e;
            }
            NewRelicSecurity.getAgent().log(LogLevel.SEVERE, String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, HttpServletHelper.SERVLET_6_0, e.getMessage()), e, FilterChain_Instrumentation.class.getName());
            NewRelicSecurity.getAgent().reportIncident(LogLevel.SEVERE, String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, HttpServletHelper.SERVLET_6_0, e.getMessage()), e, FilterChain_Instrumentation.class.getName());
        }
    }

    private boolean acquireServletLockIfPossible() {
        try {
            return HttpServletHelper.acquireServletLockIfPossible();
        } catch (Throwable ignored) {}
        return false;
    }

    private void releaseServletLock() {
        try {
            HttpServletHelper.releaseServletLock();
        } catch (Throwable e) {}
    }
}
