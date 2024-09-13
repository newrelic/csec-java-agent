package com.newrelic.agent.security.instrumentation.apache.pekko;

import com.newrelic.api.agent.Token;
import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.instrumentation.helpers.LowSeverityHelper;
import com.newrelic.api.agent.security.instrumentation.helpers.ServletHelper;
import com.newrelic.api.agent.security.schema.AgentMetaData;
import com.newrelic.api.agent.security.schema.SecurityMetaData;
import com.newrelic.api.agent.security.schema.StringUtils;
import com.newrelic.api.agent.security.schema.exceptions.NewRelicSecurityException;
import com.newrelic.api.agent.security.schema.operation.RXSSOperation;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import org.apache.pekko.http.javadsl.model.HttpRequest;

import java.util.Arrays;
import java.util.Optional;

public class PekkoCoreUtils {

    public static final String METHOD_SINGLE_REQUEST = "singleRequest";

    public static final String NR_SEC_CUSTOM_ATTRIB_OUTBOUND_REQ = "OUTBOUND_REQ_OPERATION_LOCK_PEKKO-";
    private static final String NR_SEC_CUSTOM_ATTRIB_HTTP_REQ = "HTTP_REQUEST_OPERATION_LOCK_PEKKO-";

    public static final String PEKKO_HTTP_CORE_2_13_1 = "APACHE_PEKKO_HTTP_CORE_2.13-1";

    private static final String X_FORWARDED_FOR = "x-forwarded-for";

    public static final String QUESTION_MARK = "?";

    public static boolean isServletLockAcquired() {
        try {
            return GenericHelper.isLockAcquired(NR_SEC_CUSTOM_ATTRIB_HTTP_REQ);
        } catch (Throwable ignored) {}
        return false;
    }

    public static void releaseServletLock() {
        try {
            GenericHelper.releaseLock(NR_SEC_CUSTOM_ATTRIB_HTTP_REQ);
        } catch (Throwable ignored){}
    }

    public static boolean acquireServletLockIfPossible() {
        try {
            return GenericHelper.acquireLockIfPossible(NR_SEC_CUSTOM_ATTRIB_HTTP_REQ);
        } catch (Throwable ignored){}
        return false;
    }

    public static void postProcessHttpRequest(Boolean isServletLockAcquired, StringBuilder responseBody, String contentType, int responseCode, String className, String methodName, Token token) {
        try {
            token.linkAndExpire();
            if(!isServletLockAcquired || !NewRelicSecurity.isHookProcessingActive()){
                return;
            }
            NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().setResponseContentType(contentType);
            NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().setResponseBody(responseBody);
            NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().setResponseCode(responseCode);
            ServletHelper.executeBeforeExitingTransaction();
            LowSeverityHelper.addRrequestUriToEventFilter(NewRelicSecurity.getAgent().getSecurityMetaData().getRequest());

            if(!ServletHelper.isResponseContentTypeExcluded(NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().getResponseContentType())) {
                RXSSOperation rxssOperation = new RXSSOperation(NewRelicSecurity.getAgent().getSecurityMetaData().getRequest(),
                        NewRelicSecurity.getAgent().getSecurityMetaData().getResponse(),
                        className, methodName);
                NewRelicSecurity.getAgent().registerOperation(rxssOperation);
            }
            ServletHelper.tmpFileCleanUp(NewRelicSecurity.getAgent().getSecurityMetaData().getFuzzRequestIdentifier().getTempFiles());
        } catch (Throwable e) {
            if(e instanceof NewRelicSecurityException){
                NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.SECURITY_EXCEPTION_MESSAGE, PEKKO_HTTP_CORE_2_13_1, e.getMessage()), e, PekkoCoreUtils.class.getName());
                throw e;
            }
            NewRelicSecurity.getAgent().log(LogLevel.SEVERE, String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, PEKKO_HTTP_CORE_2_13_1, e.getMessage()), e, PekkoCoreUtils.class.getName());
            NewRelicSecurity.getAgent().reportIncident(LogLevel.SEVERE, String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, PEKKO_HTTP_CORE_2_13_1, e.getMessage()), e, PekkoCoreUtils.class.getName());
        } finally {
            if(isServletLockAcquired){
                releaseServletLock();
            }
        }
    }

    public static void preProcessHttpRequest (Boolean isServletLockAcquired, HttpRequest request, StringBuilder requestBody, Token token) {
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
            if (securityRequest.isRequestParsed()) {
                return;
            }

            AgentMetaData securityAgentMetaData = securityMetaData.getMetaData();

            securityRequest.setMethod(request.method().value());
            //TODO Client IP and PORT extraction is pending

            securityRequest.setServerPort(request.getUri().getPort());

            // TODO process http request headers

            securityRequest.setProtocol(getProtocol(request.protocol().value()));

            securityRequest.setUrl(request.getUri().path());
            String queryString = null;
            Optional<String> rawQueryString = request.getUri().rawQueryString();
            if(rawQueryString.isPresent()) {
                queryString = rawQueryString.get();
            }
            if (queryString != null && !queryString.trim().isEmpty()) {
                securityRequest.setUrl(securityRequest.getUrl() + QUESTION_MARK + queryString);
            }

            securityRequest.setContentType(request.entity().getContentType().toString());

            StackTraceElement[] trace = Thread.currentThread().getStackTrace();
            securityMetaData.getMetaData().setServiceTrace(Arrays.copyOfRange(trace, 2, trace.length));
            securityRequest.setBody(requestBody);
            securityRequest.setRequestParsed(true);
        } catch (Throwable ignored){
            NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.ERROR_GENERATING_HTTP_REQUEST, PEKKO_HTTP_CORE_2_13_1, ignored.getMessage()), ignored, PekkoCoreUtils.class.getName());
        }
        finally {
            if(isServletLockAcquired()){
                releaseServletLock();
            }
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
