package security.org.eclipse.jetty11.server;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.LowSeverityHelper;
import com.newrelic.api.agent.security.instrumentation.helpers.ServletHelper;
import com.newrelic.api.agent.security.schema.AgentMetaData;
import com.newrelic.api.agent.security.schema.HttpRequest;
import com.newrelic.api.agent.security.schema.SecurityMetaData;
import com.newrelic.api.agent.security.schema.exceptions.NewRelicSecurityException;
import com.newrelic.api.agent.security.schema.operation.RXSSOperation;
import com.newrelic.api.agent.security.schema.policy.AgentPolicy;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.util.Enumeration;
import java.util.Map;

public class HttpServletHelper {

    private static final String X_FORWARDED_FOR = "x-forwarded-for";
    private static final String EMPTY = "";
    public static final String QUESTION_MARK = "?";
    public static final String SERVICE_METHOD_NAME = "handle";
    public static final String SERVICE_ASYNC_METHOD_NAME = "handleAsync";

    public static final String NR_SEC_CUSTOM_ATTRIB_NAME = "SERVLET_LOCK-";

    public static void processHttpRequestHeader(HttpServletRequest request, HttpRequest securityRequest) {
        Enumeration<String> headerNames = request.getHeaderNames();
        while (headerNames.hasMoreElements()) {
            boolean takeNextValue = false;
            String headerKey = headerNames.nextElement();
            if (headerKey != null) {
                headerKey = headerKey.toLowerCase();
            }
            AgentPolicy agentPolicy = NewRelicSecurity.getAgent().getCurrentPolicy();
            AgentMetaData agentMetaData = NewRelicSecurity.getAgent().getSecurityMetaData().getMetaData();
            if (agentPolicy != null
                    && agentPolicy.getProtectionMode().getEnabled()
                    && agentPolicy.getProtectionMode().getIpBlocking().getEnabled()
                    && agentPolicy.getProtectionMode().getIpBlocking().getIpDetectViaXFF()
                    && X_FORWARDED_FOR.equals(headerKey)) {
                takeNextValue = true;
            } else if (ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID.equals(headerKey)) {
                // TODO: May think of removing this intermediate obj and directly create K2 Identifier.
                NewRelicSecurity.getAgent().getSecurityMetaData().setFuzzRequestIdentifier(ServletHelper.parseFuzzRequestIdentifierHeader(request.getHeader(headerKey)));
            }
            String headerFullValue = EMPTY;
            Enumeration<String> headerElements = request.getHeaders(headerKey);
            while (headerElements.hasMoreElements()) {
                String headerValue = headerElements.nextElement();
                if (headerValue != null && !headerValue.trim().isEmpty()) {
                    if (takeNextValue) {
                        agentMetaData.setClientDetectedFromXFF(true);
                        securityRequest.setClientIP(headerValue);
                        agentMetaData.getIps()
                                .add(securityRequest.getClientIP());
                        securityRequest.setClientPort(EMPTY);
                        takeNextValue = false;
                    }
                    if (headerFullValue.trim().isEmpty()) {
                        headerFullValue = headerValue;
                    } else {
                        headerFullValue = String.join(";", headerFullValue, headerValue);
                    }
                }
            }
            securityRequest.getHeaders().put(headerKey, headerFullValue);
        }

    }

    public static String getTraceHeader(Map<String, String> headers) {
        String data = EMPTY;
        if (headers.containsKey(ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER) || headers.containsKey(ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER.toLowerCase())) {
            data = headers.get(ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER);
            if (data == null || data.trim().isEmpty()) {
                data = headers.get(ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER.toLowerCase());
            }
        }
        return data;
    }

    public static boolean isServletLockAcquired() {
        try {
            return NewRelicSecurity.isHookProcessingActive() &&
                    Boolean.TRUE.equals(NewRelicSecurity.getAgent().getSecurityMetaData().getCustomAttribute(getNrSecCustomAttribName(), Boolean.class));
        } catch (Throwable ignored) {
        }
        return false;
    }

    public static boolean acquireServletLockIfPossible() {
        try {
            if (NewRelicSecurity.isHookProcessingActive() &&
                    !isServletLockAcquired()) {
                NewRelicSecurity.getAgent().getSecurityMetaData().addCustomAttribute(getNrSecCustomAttribName(), true);
                return true;
            }
        } catch (Throwable ignored) {
        }
        return false;
    }

    public static void releaseServletLock() {
        try {
            if (NewRelicSecurity.isHookProcessingActive()) {
                NewRelicSecurity.getAgent().getSecurityMetaData().addCustomAttribute(getNrSecCustomAttribName(), null);
            }
        } catch (Throwable ignored) {
        }
    }

    private static String getNrSecCustomAttribName() {
        return NR_SEC_CUSTOM_ATTRIB_NAME;
    }

    public static void preprocessSecurityHook(HttpServletRequest httpServletRequest) {
        try {
            if (!NewRelicSecurity.isHookProcessingActive() || httpServletRequest == null) {
                return;
            }
            SecurityMetaData securityMetaData = NewRelicSecurity.getAgent().getSecurityMetaData();

            HttpRequest securityRequest = securityMetaData.getRequest();
            if (securityRequest.isRequestParsed()) {
                return;
            }

            AgentMetaData securityAgentMetaData = securityMetaData.getMetaData();

            securityRequest.setMethod(httpServletRequest.getMethod());
            securityRequest.setClientIP(httpServletRequest.getRemoteAddr());
            securityRequest.setServerPort(httpServletRequest.getLocalPort());

            if (securityRequest.getClientIP() != null && !securityRequest.getClientIP().trim().isEmpty()) {
                securityAgentMetaData.getIps().add(securityRequest.getClientIP());
                securityRequest.setClientPort(String.valueOf(httpServletRequest.getRemotePort()));
            }

            HttpServletHelper.processHttpRequestHeader(httpServletRequest, securityRequest);

            securityMetaData.setTracingHeaderValue(HttpServletHelper.getTraceHeader(securityRequest.getHeaders()));

            securityRequest.setProtocol(httpServletRequest.getScheme());
            securityRequest.setUrl(httpServletRequest.getRequestURI());

            // TODO: Create OutBoundHttp data here : Skipping for now.

            String queryString = httpServletRequest.getQueryString();
            if (queryString != null && !queryString.trim().isEmpty()) {
                securityRequest.setUrl(securityRequest.getUrl() + HttpServletHelper.QUESTION_MARK + queryString);
            }
            securityRequest.setContentType(httpServletRequest.getContentType());

            securityAgentMetaData.setServiceTrace(Thread.currentThread().getStackTrace());
            securityRequest.setRequestParsed(true);
        } catch (Throwable ignored) {
        }
    }

    public static void postProcessSecurityHook(HttpServletRequest request, HttpServletResponse response,
                                               String className, String methodName) {
        try {
            if (!NewRelicSecurity.isHookProcessingActive()
            ) {
                return;
            }
            //Add request URI hash to low severity event filter
            LowSeverityHelper.addRrequestUriToEventFilter(NewRelicSecurity.getAgent().getSecurityMetaData().getRequest());
            RXSSOperation rxssOperation = new RXSSOperation(NewRelicSecurity.getAgent().getSecurityMetaData().getRequest(),
                    NewRelicSecurity.getAgent().getSecurityMetaData().getResponse(),
                    className, methodName);
            NewRelicSecurity.getAgent().registerOperation(rxssOperation);
            ServletHelper.tmpFileCleanUp(NewRelicSecurity.getAgent().getSecurityMetaData().getFuzzRequestIdentifier().getTempFiles());
        } catch (Throwable e) {
            if (e instanceof NewRelicSecurityException) {
                e.printStackTrace();
                throw e;
            }
        }
    }
}
