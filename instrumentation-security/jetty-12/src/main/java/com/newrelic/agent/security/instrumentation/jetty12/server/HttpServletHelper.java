package com.newrelic.agent.security.instrumentation.jetty12.server;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.instrumentation.helpers.ICsecApiConstants;
import com.newrelic.api.agent.security.instrumentation.helpers.LowSeverityHelper;
import com.newrelic.api.agent.security.instrumentation.helpers.ServletHelper;
import com.newrelic.api.agent.security.schema.AgentMetaData;
import com.newrelic.api.agent.security.schema.HttpRequest;
import com.newrelic.api.agent.security.schema.SecurityMetaData;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.security.schema.exceptions.NewRelicSecurityException;
import com.newrelic.api.agent.security.schema.operation.RXSSOperation;
import com.newrelic.api.agent.security.schema.policy.AgentPolicy;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import org.eclipse.jetty.http.HttpFields;
import org.eclipse.jetty.http.HttpHeader;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.Response;

import java.util.Arrays;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

public class HttpServletHelper {

    private static final String X_FORWARDED_FOR = "x-forwarded-for";
    private static final String EMPTY = "";
    public static final String SERVICE_METHOD_NAME = "handle";

    private static final String NR_SEC_CUSTOM_ATTRIB_NAME = "SERVLET_LOCK-";
    public static final String JETTY_12 = "JETTY-12";

    private static void processHttpRequestHeader(Request request, HttpRequest securityRequest) {
        HttpFields headers = request.getHeaders();
        if (headers!=null){
            Set<String> headerKeys = headers.getFieldNamesCollection();
            Iterator<String> headerKeysIterator = headerKeys.iterator();
            while(headerKeysIterator.hasNext()){
                boolean takeNextValue = false;
                String headerKey = headerKeysIterator.next();
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
                    NewRelicSecurity.getAgent().getSecurityMetaData().setFuzzRequestIdentifier(ServletHelper.parseFuzzRequestIdentifierHeader(request.getHeaders().get(headerKey)));
                } else if(GenericHelper.CSEC_PARENT_ID.equals(headerKey)) {
                    NewRelicSecurity.getAgent().getSecurityMetaData()
                            .addCustomAttribute(GenericHelper.CSEC_PARENT_ID, request.getHeaders().get(headerKey));
                } else if (ICsecApiConstants.NR_CSEC_JAVA_HEAD_REQUEST.equals(headerKey)) {
                    NewRelicSecurity.getAgent().getSecurityMetaData()
                            .addCustomAttribute(ICsecApiConstants.NR_CSEC_JAVA_HEAD_REQUEST, true);
                }

                String headerFullValue = EMPTY;
                String headerValue = request.getHeaders().get(headerKey);

                if (headerValue != null && !headerValue.trim().isEmpty()) {
                    if (takeNextValue) {
                        agentMetaData.setClientDetectedFromXFF(true);
                        securityRequest.setClientIP(headerValue);
                        agentMetaData.getIps()
                                .add(securityRequest.getClientIP());
                        securityRequest.setClientPort(EMPTY);
                    }
                    if (headerFullValue.trim().isEmpty()) {
                        headerFullValue = headerValue;
                    } else {
                        headerFullValue = String.join(";", headerFullValue, headerValue);
                    }
                }
                securityRequest.getHeaders().put(headerKey, headerFullValue);
            }
        }
    }

    private static String getTraceHeader(Map<String, String> headers) {
        String data = EMPTY;
        if (headers.containsKey(ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER) || headers.containsKey(ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER.toLowerCase())) {
            data = headers.get(ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER);
            if (data == null || data.trim().isEmpty()) {
                data = headers.get(ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER.toLowerCase());
            }
        }
        return data;
    }


    public static boolean acquireServletLockIfPossible() {
        return GenericHelper.acquireLockIfPossible(VulnerabilityCaseType.REFLECTED_XSS, getNrSecCustomAttribName());
    }

    public static void releaseServletLock() {
        GenericHelper.releaseLock(getNrSecCustomAttribName());
    }

    private static String getNrSecCustomAttribName() {
        return NR_SEC_CUSTOM_ATTRIB_NAME + Thread.currentThread().getId();
    }

    public static void preprocessSecurityHook(Request request) {
        try {
            if (request == null) {
                return;
            }
            SecurityMetaData securityMetaData = NewRelicSecurity.getAgent().getSecurityMetaData();
            HttpRequest securityRequest = securityMetaData.getRequest();


            AgentMetaData securityAgentMetaData = securityMetaData.getMetaData();

            securityRequest.setMethod(request.getMethod());
            securityRequest.setClientIP(Request.getRemoteAddr(request));
            securityRequest.setServerPort(Request.getLocalPort(request));

            if (securityRequest.getClientIP() != null && !securityRequest.getClientIP().trim().isEmpty()) {
                securityAgentMetaData.getIps().add(securityRequest.getClientIP());
                securityRequest.setClientPort(String.valueOf(Request.getRemotePort(request)));
            }

            HttpServletHelper.processHttpRequestHeader(request, securityRequest);

            securityMetaData.setTracingHeaderValue(HttpServletHelper.getTraceHeader(securityRequest.getHeaders()));

            securityRequest.setProtocol(request.getHttpURI().getScheme());

            // TODO: Create OutBoundHttp data here : Skipping for now.

            String url = request.getHttpURI().asString();
            if (url != null && !url.trim().isEmpty()) {
                securityRequest.setUrl(url);
            }
            securityRequest.setContentType(request.getHeaders().get(HttpHeader.CONTENT_TYPE));

            StackTraceElement[] trace = Thread.currentThread().getStackTrace();
            securityMetaData.getMetaData().setServiceTrace(Arrays.copyOfRange(trace, 2, trace.length));
            securityRequest.setRequestParsed(true);
        } catch (Throwable e) {
            NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.ERROR_GENERATING_HTTP_REQUEST, JETTY_12, e.getMessage()), e, HttpServletHelper.class.getName());
        }
    }

    public static void postProcessSecurityHook(Request request, Response response, String className, String methodName) {
        try {
            if(NewRelicSecurity.getAgent().getIastDetectionCategory().getRxssEnabled()){
                return;
            }
            if (!NewRelicSecurity.isHookProcessingActive()) {
                return;
            }
            NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().setResponseCode(response.getStatus());
//            ServletHelper.executeBeforeExitingTransaction();
            //Add request URI hash to low severity event filter
            LowSeverityHelper.addRrequestUriToEventFilter(NewRelicSecurity.getAgent().getSecurityMetaData().getRequest());
            RXSSOperation rxssOperation = new RXSSOperation(NewRelicSecurity.getAgent().getSecurityMetaData().getRequest(),
                    NewRelicSecurity.getAgent().getSecurityMetaData().getResponse(),
                    className, methodName);
            NewRelicSecurity.getAgent().registerOperation(rxssOperation);
            ServletHelper.tmpFileCleanUp(NewRelicSecurity.getAgent().getSecurityMetaData().getFuzzRequestIdentifier().getTempFiles());
        } catch (Throwable e) {
            if (e instanceof NewRelicSecurityException) {
                NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.SECURITY_EXCEPTION_MESSAGE, JETTY_12, e.getMessage()), e, HttpServletHelper.class.getName());
                throw e;
            }
            NewRelicSecurity.getAgent().log(LogLevel.SEVERE, String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, JETTY_12, e.getMessage()), e, HttpServletHelper.class.getName());
            NewRelicSecurity.getAgent().reportIncident(LogLevel.SEVERE, String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, JETTY_12, e.getMessage()), e, HttpServletHelper.class.getName());
        }
    }
}
