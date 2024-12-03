package akka.http.scaladsl.server;

import akka.http.javadsl.model.HttpHeader;
import akka.http.scaladsl.model.HttpRequest;
import com.newrelic.api.agent.Token;
import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.instrumentation.helpers.ICsecApiConstants;
import com.newrelic.api.agent.security.instrumentation.helpers.LowSeverityHelper;
import com.newrelic.api.agent.security.instrumentation.helpers.ServletHelper;
import com.newrelic.api.agent.security.schema.AgentMetaData;
import com.newrelic.api.agent.security.schema.SecurityMetaData;
import com.newrelic.api.agent.security.schema.StringUtils;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.security.schema.exceptions.NewRelicSecurityException;
import com.newrelic.api.agent.security.schema.operation.RXSSOperation;
import com.newrelic.api.agent.security.schema.policy.AgentPolicy;
import com.newrelic.api.agent.security.utils.logging.LogLevel;

import java.util.Iterator;
import java.util.Map;
import java.util.NoSuchElementException;

public class AkkaCoreUtils {

    public static final String NR_SEC_CUSTOM_ATTRIB_NAME = "HTTPREQUEST_OPERATION_LOCK_AKKA-";
    public static final String AKKA_HTTP_10_0_0 = "AKKA_HTTP_10.0.0";
    private static final String X_FORWARDED_FOR = "x-forwarded-for";
    private static final String EMPTY = "";
    private static final String QUESTION_MARK = "?";

    public static boolean acquireServletLockIfPossible() {
        return GenericHelper.acquireLockIfPossible(VulnerabilityCaseType.REFLECTED_XSS, NR_SEC_CUSTOM_ATTRIB_NAME);
    }

    public static void postProcessHttpRequest(Boolean isServletLockAcquired, StringBuilder responseBody, String contentType, String className, String methodName, Token token) {
        if(NewRelicSecurity.getAgent().getIastDetectionCategory().getRxssEnabled()){
            return;
        }
        try {
            token.linkAndExpire();
            ServletHelper.executeBeforeExitingTransaction();
            if(!isServletLockAcquired || !NewRelicSecurity.isHookProcessingActive() || Boolean.TRUE.equals(NewRelicSecurity.getAgent().getSecurityMetaData().getCustomAttribute("RXSS_PROCESSED", Boolean.class))){
                return;
            }
            NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().setResponseContentType(contentType);
            NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().setResponseBody(responseBody);
            LowSeverityHelper.addRrequestUriToEventFilter(NewRelicSecurity.getAgent().getSecurityMetaData().getRequest());

            RXSSOperation rxssOperation = new RXSSOperation(NewRelicSecurity.getAgent().getSecurityMetaData().getRequest(),
                    NewRelicSecurity.getAgent().getSecurityMetaData().getResponse(),
                    className, methodName);
            NewRelicSecurity.getAgent().registerOperation(rxssOperation);
            ServletHelper.tmpFileCleanUp(NewRelicSecurity.getAgent().getSecurityMetaData().getFuzzRequestIdentifier().getTempFiles());
        } catch (Throwable e) {
            NewRelicSecurity.getAgent().log(LogLevel.SEVERE, String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, AKKA_HTTP_10_0_0, e.getMessage()), e, AkkaCoreUtils.class.getName());
            NewRelicSecurity.getAgent().reportIncident(LogLevel.SEVERE, String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, AKKA_HTTP_10_0_0, e.getMessage()), e, AkkaCoreUtils.class.getName());
            if(e instanceof NewRelicSecurityException){
                NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.SECURITY_EXCEPTION_MESSAGE, AKKA_HTTP_10_0_0, e.getMessage()), e, AkkaCoreUtils.class.getName());
                throw e;
            }
        } finally {
            if(isServletLockAcquired){
                GenericHelper.releaseLock(NR_SEC_CUSTOM_ATTRIB_NAME);
            }
        }
    }

    public static void preProcessHttpRequest (Boolean isServletLockAcquired, HttpRequest httpRequest, StringBuilder requestBody, Token token) {
        if(!isServletLockAcquired) {
            return;
        }

        try {
            token.linkAndExpire();
            if (!NewRelicSecurity.isHookProcessingActive()) {
                return;
            }
            SecurityMetaData securityMetaData = NewRelicSecurity.getAgent().getSecurityMetaData();

            com.newrelic.api.agent.security.schema.HttpRequest securityRequest = securityMetaData.getRequest();

            AgentMetaData securityAgentMetaData = securityMetaData.getMetaData();

            securityRequest.setMethod(httpRequest.method().value());
            //TODO Client IP and PORT extraction is pending

            securityRequest.setServerPort(httpRequest.getUri().port());

            processHttpRequestHeader(httpRequest, securityRequest);

            securityMetaData.setTracingHeaderValue(getTraceHeader(securityRequest.getHeaders()));

            securityRequest.setProtocol(getProtocol(httpRequest.protocol().value()));

            securityRequest.setUrl(httpRequest.getUri().path());
            String queryString = null;
            try {
                queryString = httpRequest.getUri().rawQueryString().get();
            } catch (NoSuchElementException ignored) {
                // ignore NoSuchElementException there is no value present in rawQueryString
            } finally {
                if (queryString != null && !queryString.trim().isEmpty()) {
                    securityRequest.setUrl(securityRequest.getUrl() + QUESTION_MARK + queryString);
                }
            }

            securityRequest.setContentType(httpRequest.entity().getContentType().toString());

            securityAgentMetaData.setServiceTrace(Thread.currentThread().getStackTrace());
            securityRequest.setBody(requestBody);
            securityRequest.setRequestParsed(true);
        } catch (Throwable ignored){
            NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.ERROR_GENERATING_HTTP_REQUEST, AKKA_HTTP_10_0_0, ignored.getMessage()), ignored, AkkaCoreUtils.class.getName());
        }
        finally {
            if(GenericHelper.isLockAcquired(AkkaCoreUtils.NR_SEC_CUSTOM_ATTRIB_NAME)){
                GenericHelper.releaseLock(NR_SEC_CUSTOM_ATTRIB_NAME);
            }
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

    public static void processHttpRequestHeader(HttpRequest request, com.newrelic.api.agent.security.schema.HttpRequest securityRequest){
        Iterator<HttpHeader> headers = request.getHeaders().iterator();
        while (headers.hasNext()) {
            boolean takeNextValue = false;
            HttpHeader nextHeader = headers.next();
            String headerKey = nextHeader.name();
            if(headerKey != null){
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
                NewRelicSecurity.getAgent().getSecurityMetaData()
                        .setFuzzRequestIdentifier(ServletHelper.parseFuzzRequestIdentifierHeader(nextHeader.value()));
            } else if(GenericHelper.CSEC_PARENT_ID.equals(headerKey)) {
                NewRelicSecurity.getAgent().getSecurityMetaData()
                        .addCustomAttribute(GenericHelper.CSEC_PARENT_ID, request.getHeader(headerKey).get().value());
            } else if (ICsecApiConstants.NR_CSEC_JAVA_HEAD_REQUEST.equals(headerKey)) {
                NewRelicSecurity.getAgent().getSecurityMetaData()
                        .addCustomAttribute(ICsecApiConstants.NR_CSEC_JAVA_HEAD_REQUEST, true);
            }
            String headerFullValue = nextHeader.value();
            if (headerFullValue != null && !headerFullValue.trim().isEmpty()) {
                if (takeNextValue) {
                    agentMetaData.setClientDetectedFromXFF(true);
                    securityRequest.setClientIP(headerFullValue);
                    agentMetaData.getIps()
                            .add(securityRequest.getClientIP());
                    securityRequest.setClientPort(EMPTY);
                    takeNextValue = false;
                }
            }
            securityRequest.getHeaders().put(headerKey, headerFullValue);
        }

    }

    private static String getProtocol(String value) {
        if(StringUtils.containsIgnoreCase(value, "https")){
            return "https";
        } else if (StringUtils.containsIgnoreCase(value, "http")) {
            return "http";
        } else {
            return value;
        }
    }
}
