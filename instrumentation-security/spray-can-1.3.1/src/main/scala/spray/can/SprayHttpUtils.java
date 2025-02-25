package spray.can;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.instrumentation.helpers.ICsecApiConstants;
import com.newrelic.api.agent.security.instrumentation.helpers.LowSeverityHelper;
import com.newrelic.api.agent.security.instrumentation.helpers.ServletHelper;
import com.newrelic.api.agent.security.schema.AgentMetaData;
import com.newrelic.api.agent.security.schema.SecurityMetaData;
import com.newrelic.api.agent.security.schema.StringUtils;
import com.newrelic.api.agent.security.schema.exceptions.NewRelicSecurityException;
import com.newrelic.api.agent.security.schema.operation.RXSSOperation;
import com.newrelic.api.agent.security.schema.policy.AgentPolicy;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import scala.collection.Iterator;
import scala.collection.immutable.List;
import spray.http.*;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Map;

public class SprayHttpUtils {

    private static final String QUESTION_MARK = "?";

    private static final String X_FORWARDED_FOR = "x-forwarded-for";
    public static final String SPRAY_CAN_1_3_1 = "SPRAY-CAN-1.3.1";

    public static String getNrSecCustomAttribName() {
        return "SPRAY-CAN-" + Thread.currentThread().getId();
    }
    public static String getNrSecCustomAttribNameForResponse() {
        return "SPRAY-CAN-RXSS" + Thread.currentThread().getId();
    }

    public static void preProcessRequestHook(HttpRequest request) {
        try {
            SecurityMetaData securityMetaData = NewRelicSecurity.getAgent().getSecurityMetaData();
            com.newrelic.api.agent.security.schema.HttpRequest securityRequest = securityMetaData.getRequest();

            securityRequest.setMethod(request.method().name());
            securityRequest.setProtocol(request.uri().scheme());
            securityRequest.setUrl(processURL(request.uri()));
            securityRequest.setServerPort(request.uri().effectivePort());
            processHttpRequestHeader(request.headers(), securityRequest);

            securityMetaData.setTracingHeaderValue(getTraceHeader(securityRequest.getHeaders()));

            if (!request.entity().isEmpty()) {
                if (request.entity() instanceof HttpEntity.NonEmpty) {
                    securityRequest.setContentType(((HttpEntity.NonEmpty) request.entity()).contentType().value());
                }
                securityRequest.setBody(new StringBuilder(request.entity().data().asString(StandardCharsets.UTF_8)));
            }

            StackTraceElement[] trace = Thread.currentThread().getStackTrace();
            securityMetaData.getMetaData().setServiceTrace(Arrays.copyOfRange(trace, 2, trace.length));
            securityRequest.setRequestParsed(true);
        } catch (Exception e){
            NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.ERROR_GENERATING_HTTP_REQUEST, SPRAY_CAN_1_3_1, e.getMessage()), e, SprayHttpUtils.class.getName());
        }
    }

    private static String getTraceHeader(Map<String, String> headers) {
        String data = StringUtils.EMPTY;
        if (headers.containsKey(ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER) || headers.containsKey(ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER.toLowerCase())) {
            data = headers.get(ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER);
            if (data == null || data.trim().isEmpty()) {
                data = headers.get(ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER.toLowerCase());
            }
        }
        return data;
    }

    private static void processHttpRequestHeader(List<HttpHeader> headers, com.newrelic.api.agent.security.schema.HttpRequest securityRequest) {
        Iterator<HttpHeader> headerIterator = headers.iterator();
        while (headerIterator.hasNext()){
            HttpHeader element = headerIterator.next();
            String headerKey = element.lowercaseName();
            String headerValue = element.value();
            boolean takeNextValue = false;
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
                NewRelicSecurity.getAgent().getSecurityMetaData().setFuzzRequestIdentifier(ServletHelper.parseFuzzRequestIdentifierHeader(headerValue));
            } else if(GenericHelper.CSEC_PARENT_ID.equals(headerKey)) {
                NewRelicSecurity.getAgent().getSecurityMetaData()
                        .addCustomAttribute(GenericHelper.CSEC_PARENT_ID, headerValue);
            } else if (ICsecApiConstants.NR_CSEC_JAVA_HEAD_REQUEST.equals(headerKey)) {
                NewRelicSecurity.getAgent().getSecurityMetaData()
                        .addCustomAttribute(ICsecApiConstants.NR_CSEC_JAVA_HEAD_REQUEST, true);
            }
            if (takeNextValue) {
                agentMetaData.setClientDetectedFromXFF(true);
                securityRequest.setClientIP(headerValue);
                agentMetaData.getIps()
                        .add(securityRequest.getClientIP());
            }
            securityRequest.getHeaders().put(headerKey, headerValue);
        }
    }

    private static String processURL(Uri uri) {
        String path = uri.path().toString();
        String queryString = StringUtils.substringAfter(uri.toString(), QUESTION_MARK);
        if(StringUtils.isBlank(queryString)){
            return path;
        } else {
            return path + QUESTION_MARK + queryString;
        }
    }

    public static void postProcessSecurityHook(HttpResponse httpResponse, String className, String methodName) {
        try {
            if (!NewRelicSecurity.isHookProcessingActive()
            ) {
                return;
            }
            NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().setStatusCode(httpResponse.status().intValue());

//            ServletHelper.executeBeforeExitingTransaction();
            //Add request URI hash to low severity event filter
            LowSeverityHelper.addRrequestUriToEventFilter(NewRelicSecurity.getAgent().getSecurityMetaData().getRequest());

            if(!ServletHelper.isResponseContentTypeExcluded(NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().getResponseContentType())) {
                RXSSOperation rxssOperation = new RXSSOperation(NewRelicSecurity.getAgent().getSecurityMetaData().getRequest(),
                        NewRelicSecurity.getAgent().getSecurityMetaData().getResponse(),
                        className, methodName);
                NewRelicSecurity.getAgent().registerOperation(rxssOperation);
            }
            ServletHelper.tmpFileCleanUp(NewRelicSecurity.getAgent().getSecurityMetaData().getFuzzRequestIdentifier().getTempFiles());
        } catch (Throwable e) {
            if (e instanceof NewRelicSecurityException) {
                NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.SECURITY_EXCEPTION_MESSAGE, SPRAY_CAN_1_3_1, e.getMessage()), e, SprayHttpUtils.class.getName());
                throw e;
            }
            NewRelicSecurity.getAgent().log(LogLevel.SEVERE, String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, SPRAY_CAN_1_3_1, e.getMessage()), e, SprayHttpUtils.class.getName());
            NewRelicSecurity.getAgent().reportIncident(LogLevel.SEVERE, String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, SPRAY_CAN_1_3_1, e.getMessage()), e, SprayHttpUtils.class.getName());
        }
    }

    public static void processResponseHeaders(List<HttpHeader> headers, com.newrelic.api.agent.security.schema.HttpResponse response) {
        Iterator<HttpHeader> headerIterator = headers.iterator();
        while (headerIterator.hasNext()) {
            HttpHeader element = headerIterator.next();
            String headerKey = element.name();
            String headerValue = element.value();
            response.getHeaders().put(headerKey, headerValue);
        }
    }
}
