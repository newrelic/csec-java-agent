package com.newrelic.agent.security.instrumentation.spring.client5;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.instrumentation.helpers.ServletHelper;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.StringUtils;
import com.newrelic.api.agent.security.schema.exceptions.NewRelicSecurityException;
import com.newrelic.api.agent.security.schema.operation.SSRFOperation;
import com.newrelic.api.agent.security.utils.SSRFUtils;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import org.springframework.http.HttpMethod;
import org.springframework.web.reactive.function.client.ClientRequest;

import java.net.URI;
import java.util.ArrayList;

public class SpringWebClientHelper {

    public static final String NR_SEC_CUSTOM_ATTRIB_NAME = "SPRING_CLIENT_OPERATION_LOCK-";
    public static final String METHOD_EXECHANGE = "exchange";

    public static final String SPRING_WEBCLIENT_5_0 = "spring-webclient-5.0";
    public static final String SPRING_WEB_CLIENT_REQUEST_LIST_CUSTOM_ATTRIB = "SPRING-WEB-CLIENT-REQUEST-LIST";

    public static String getNrSecCustomAttribName() {
        return NR_SEC_CUSTOM_ATTRIB_NAME + Thread.currentThread().getId();
    }

    public static AbstractOperation preprocessSecurityHook(URI url, HttpMethod method, String className, String methodName) {
        try {
            if (url == null || url.getPath().isEmpty()) {
                return null;
            }
            ArrayList<String> springClientRequestURIs = NewRelicSecurity.getAgent().getSecurityMetaData().getCustomAttribute(SPRING_WEB_CLIENT_REQUEST_LIST_CUSTOM_ATTRIB, ArrayList.class);
            if (springClientRequestURIs == null){
                springClientRequestURIs = new ArrayList<>();
            }
            if (!springClientRequestURIs.contains(url.toString())) {
                SSRFOperation ssrfOperation = new SSRFOperation(url.toString(), className, methodName);
                NewRelicSecurity.getAgent().getSecurityMetaData().getMetaData().setFromJumpRequiredInStackTrace(3);
                NewRelicSecurity.getAgent().registerOperation(ssrfOperation);
                springClientRequestURIs.add(url.toString());
                NewRelicSecurity.getAgent().getSecurityMetaData().addCustomAttribute(SPRING_WEB_CLIENT_REQUEST_LIST_CUSTOM_ATTRIB, springClientRequestURIs);
                return ssrfOperation;
            }
        } catch (Throwable e) {
            if (e instanceof NewRelicSecurityException) {
                NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.SECURITY_EXCEPTION_MESSAGE, SPRING_WEBCLIENT_5_0, e.getMessage()), e, SpringWebClientHelper.class.getName());
                throw e;
            }
            NewRelicSecurity.getAgent().log(LogLevel.SEVERE, String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, SPRING_WEBCLIENT_5_0, e.getMessage()), e, SpringWebClientHelper.class.getName());
            NewRelicSecurity.getAgent().reportIncident(LogLevel.SEVERE, String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, SPRING_WEBCLIENT_5_0, e.getMessage()), e, SpringWebClientHelper.class.getName());
        }
        return null;
    }

    public static void registerExitOperation(boolean isProcessingAllowed, AbstractOperation operation) {
        try {
            if (operation == null || !isProcessingAllowed || !NewRelicSecurity.isHookProcessingActive() ||
                    NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty() || GenericHelper.skipExitEvent()
            ) {
                return;
            }
            NewRelicSecurity.getAgent().registerExitEvent(operation);
        } catch (Throwable e) {
            NewRelicSecurity.getAgent().log(LogLevel.FINEST, String.format(GenericHelper.EXIT_OPERATION_EXCEPTION_MESSAGE, SPRING_WEBCLIENT_5_0, e.getMessage()), e, SpringWebClientHelper.class.getName());
        }
    }

    public static ClientRequest addSecurityHeaders(ClientRequest request, AbstractOperation operation) {
        if (operation == null || request == null) {
            return null;
        }
        ClientRequest.Builder requestBuilder = ClientRequest.from(request);

        String iastHeader = NewRelicSecurity.getAgent().getSecurityMetaData().getFuzzRequestIdentifier().getRaw();
        if (iastHeader != null && !iastHeader.trim().isEmpty()) {
            requestBuilder.header(ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID, iastHeader);
        }
        String csecParaentId = NewRelicSecurity.getAgent().getSecurityMetaData().getCustomAttribute(GenericHelper.CSEC_PARENT_ID, String.class);
        if(StringUtils.isNotBlank(csecParaentId)){
            requestBuilder.header(GenericHelper.CSEC_PARENT_ID, csecParaentId);
        }

        if (operation.getApiID() != null && !operation.getApiID().trim().isEmpty() &&
                operation.getExecutionId() != null && !operation.getExecutionId().trim().isEmpty()) {
            // Add Security distributed tracing header
            requestBuilder.header(ServletHelper.CSEC_DISTRIBUTED_TRACING_HEADER,
                    SSRFUtils.generateTracingHeaderValue(NewRelicSecurity.getAgent().getSecurityMetaData()
                                    .getTracingHeaderValue(),
                            operation.getApiID(), operation.getExecutionId(),
                            NewRelicSecurity.getAgent().getAgentUUID()));
        }
        return requestBuilder.build();

    }
}
