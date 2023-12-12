package akka.http.scaladsl;

import akka.http.javadsl.model.HttpHeader;
import akka.http.scaladsl.model.HttpRequest;
import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.instrumentation.helpers.ServletHelper;
import com.newrelic.api.agent.security.schema.AgentMetaData;
import com.newrelic.api.agent.security.schema.SecurityMetaData;
import com.newrelic.api.agent.security.schema.policy.AgentPolicy;

import java.util.Iterator;
import java.util.Map;

public class AkkaCoreUtils {

    public static final String METHOD_SINGLE_REQUEST_IMPL = "singleRequestImpl";

    public static final String NR_SEC_CUSTOM_ATTRIB_NAME = "HTTPREQUEST_OPERATION_LOCK_AKKA-";

    private static final String X_FORWARDED_FOR = "x-forwarded-for";
    private static final String EMPTY = "";

    public static boolean isServletLockAcquired() {
        try {
            return NewRelicSecurity.isHookProcessingActive() &&
                    Boolean.TRUE.equals(NewRelicSecurity.getAgent().getSecurityMetaData().getCustomAttribute(getNrSecCustomAttribName(), Boolean.class));
        } catch (Throwable ignored) {}
        return false;
    }

    public static void releaseServletLock() {
        try {
            if(NewRelicSecurity.isHookProcessingActive()) {
                NewRelicSecurity.getAgent().getSecurityMetaData().addCustomAttribute(getNrSecCustomAttribName(), null);
            }
        } catch (Throwable ignored){}
    }

    private static String getNrSecCustomAttribName() {
        return NR_SEC_CUSTOM_ATTRIB_NAME + Thread.currentThread().getId();
    }

    public static boolean acquireServletLockIfPossible() {
        try {
            if (NewRelicSecurity.isHookProcessingActive() &&
                    !isServletLockAcquired()) {
                NewRelicSecurity.getAgent().getSecurityMetaData().addCustomAttribute(getNrSecCustomAttribName(), true);
                return true;
            }
        } catch (Throwable ignored){}
        return false;
    }

    public static void preProcessHttpRequest (HttpRequest httpRequest, String requestBody) {
        boolean isServletLockAcquired = acquireServletLockIfPossible();
        if(!isServletLockAcquired) {
            return;
        }

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

            securityRequest.setMethod(httpRequest.method().value());
            //TODO Client IP and PORT extraction is pending

//            securityRequest.setClientIP();
            securityRequest.setServerPort(httpRequest.getUri().getPort());

            processHttpRequestHeader(httpRequest, securityRequest);

            securityMetaData.setTracingHeaderValue(getTraceHeader(securityRequest.getHeaders()));

            securityRequest.setProtocol(httpRequest.protocol().value());
            securityRequest.setUrl(httpRequest.getUri().toString());
            securityRequest.setContentType(httpRequest.entity().getContentType().toString());

            securityAgentMetaData.setServiceTrace(Thread.currentThread().getStackTrace());
            securityRequest.setRequestParsed(true);
        } catch (Throwable ignored){}
        finally {
            if(isServletLockAcquired()){
                releaseServletLock();
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
                        .addCustomAttribute(GenericHelper.CSEC_PARENT_ID, request.getHeader(headerKey));
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
}
