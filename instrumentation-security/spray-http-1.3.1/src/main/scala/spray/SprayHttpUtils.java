package spray;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
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

public class SprayHttpUtils {

    public static final String QUESTION_MARK = "?";

    private static final String X_FORWARDED_FOR = "x-forwarded-for";
    public static final String SPRAY_HTTP_1_3_1 = "SPRAY-HTTP-1.3.1";

    public static String getNrSecCustomAttribName() {
        return "SPRAY-HTTP-" + Thread.currentThread().getId();
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

    public static void preProcessRequestHook(HttpRequest request) {
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
            securityRequest.setMethod(request.method().name());
            securityRequest.setProtocol(request.uri().scheme());
            securityRequest.setUrl(processURL(request.uri()));
            securityRequest.setServerPort(request.uri().effectivePort());
            processHttpRequestHeader(request.headers(), securityRequest);
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
            NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.ERROR_GENERATING_HTTP_REQUEST, SPRAY_HTTP_1_3_1, e.getMessage()), e, SprayHttpUtils.class.getName());
            e.printStackTrace();
        }
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
        String suri = uri.toString();
        String queryString = StringUtils.substringAfter(suri, QUESTION_MARK);
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
            e.printStackTrace();
            if (e instanceof NewRelicSecurityException) {
                NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.SECURITY_EXCEPTION_MESSAGE, SPRAY_HTTP_1_3_1, e.getMessage()), e, SprayHttpUtils.class.getName());
                throw e;
            }
            NewRelicSecurity.getAgent().log(LogLevel.SEVERE, String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, SPRAY_HTTP_1_3_1, e.getMessage()), e, SprayHttpUtils.class.getName());
            NewRelicSecurity.getAgent().reportIncident(LogLevel.SEVERE, String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, SPRAY_HTTP_1_3_1, e.getMessage()), e, SprayHttpUtils.class.getName());
        }
    }
}
