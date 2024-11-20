package security.io.netty400.utils;

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
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.http.FullHttpResponse;
import io.netty.handler.codec.http.HttpContent;
import io.netty.handler.codec.http.HttpHeaders;
import io.netty.handler.codec.http.HttpRequest;
import io.netty.handler.codec.http.HttpResponse;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class NettyUtils {
    public static final String NETTY_4_0_0 = "NETTY-4.0.0";
    public static String NR_SEC_CUSTOM_ATTRIB_NAME = "NETTY-4.8-REQ-BODY-TRACKER";
    public static String NR_SEC_NETTY_OPERATIONAL_LOCK = "NR_SEC_NETTY_OPERATIONAL_LOCK_INBOUND";
    public static String NR_SEC_NETTY_OPERATIONAL_LOCK_OUTBOUND = "NR_SEC_NETTY_OPERATIONAL_LOCK_OUTBOUND";
    private static final String X_FORWARDED_FOR = "x-forwarded-for";
    private static final String EMPTY = "";
    public static final String WRITE_METHOD_NAME = "write";

    public static final String IO_NETTY = "io.netty.";
    private static final String ERROR_GETTING_SERVER_PORT = "Instrumentation library: %s , error while getting server port %s";
    private static final String ERROR_PARSING_HTTP_RESPONSE_DATA = "Instrumentation library: %s , error while parsing HTTP response data : %s";

    public static void processSecurityRequest(ChannelHandlerContext ctx, Object msg, String className) {
        try {
            if (msg instanceof HttpRequest) {
                SecurityMetaData securityMetaData = NewRelicSecurity.getAgent().getSecurityMetaData();
                com.newrelic.api.agent.security.schema.HttpRequest securityRequest =
                        securityMetaData.getRequest();

                securityRequest.setMethod(((HttpRequest) msg).getMethod().name());
                securityRequest.setUrl(((HttpRequest) msg).getUri());
                setClientAddressDetails(securityMetaData, ctx.channel().remoteAddress().toString());
                setServerPortDetails(securityRequest, ctx.channel().localAddress().toString());
                processHttpRequestHeader((HttpRequest)msg, securityRequest);
                securityMetaData.setTracingHeaderValue(getTraceHeader(securityRequest.getHeaders()));

                securityRequest.setProtocol(((HttpRequest) msg).getProtocolVersion().protocolName().toLowerCase());
                securityRequest.setContentType(securityRequest.getHeaders().get("content-type"));
                if (!securityMetaData.getMetaData().isUserLevelServiceMethodEncountered(IO_NETTY)){
                    StackTraceElement[] stack = Thread.currentThread().getStackTrace();
                    securityMetaData.getMetaData().setServiceTrace(Arrays.copyOfRange(stack, 2, stack.length));
                }
                securityRequest.setRequestParsed(true);
            }
            if (msg instanceof HttpContent) {
                Integer reqBodyTrackerContextId = NewRelicSecurity.getAgent().getSecurityMetaData()
                        .getCustomAttribute(NR_SEC_CUSTOM_ATTRIB_NAME, Integer.class);
                if (reqBodyTrackerContextId == null) {
                    reqBodyTrackerContextId = ctx.hashCode();
                    NewRelicSecurity.getAgent().getSecurityMetaData()
                            .addCustomAttribute(NR_SEC_CUSTOM_ATTRIB_NAME, reqBodyTrackerContextId);
                }
                if (reqBodyTrackerContextId.equals(ctx.hashCode())) {
                    com.newrelic.api.agent.security.schema.HttpRequest securityRequest =
                            NewRelicSecurity.getAgent().getSecurityMetaData().getRequest();
                    securityRequest.getBody().append(((HttpContent) msg).content().toString(StandardCharsets.UTF_8));
                }
            }
        } catch (Throwable ignored) {
            NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.ERROR_PARSING_HTTP_REQUEST_DATA, NETTY_4_0_0, ignored.getMessage()), ignored, NettyUtils.class.getName());
        }
    }

    private static void setServerPortDetails(com.newrelic.api.agent.security.schema.HttpRequest securityRequest, String address) {
        try {
            String port = StringUtils.substringAfterLast(address, ":");
            if (StringUtils.isBlank(port)) {
                return;
            }
            securityRequest.setServerPort(Integer.parseInt(port));
        } catch (Throwable throwable) {
            NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(ERROR_GETTING_SERVER_PORT, NETTY_4_0_0, throwable.getMessage()), throwable, NettyUtils.class.getName());
        }
    }

    private static void setClientAddressDetails(SecurityMetaData securityMetaData, String address) {
        if (StringUtils.isBlank(address)) {
            return;
        }
        com.newrelic.api.agent.security.schema.HttpRequest securityRequest = securityMetaData.getRequest();
        address = StringUtils.replace(address, "/", "");
        securityRequest.setClientIP(StringUtils.substringBeforeLast(address, ":"));
        securityRequest.setClientPort(StringUtils.substringAfterLast(address, ":"));
        if (StringUtils.isNotBlank(securityRequest.getClientIP())) {
            securityMetaData.getMetaData().getIps().add(securityRequest.getClientIP());
        }
    }

    public static void processHttpRequestHeader(HttpRequest request, com.newrelic.api.agent.security.schema.HttpRequest securityRequest) {
        Set<String> headerNames = request.headers().names();
        for (String headerKey : headerNames) {
            boolean takeNextValue = false;
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
                NewRelicSecurity.getAgent().getSecurityMetaData().setFuzzRequestIdentifier(ServletHelper.parseFuzzRequestIdentifierHeader(request.headers().get(headerKey)));
            } else if(GenericHelper.CSEC_PARENT_ID.equals(headerKey)) {
                NewRelicSecurity.getAgent().getSecurityMetaData()
                        .addCustomAttribute(GenericHelper.CSEC_PARENT_ID, request.headers().get(headerKey));
            } else if (ICsecApiConstants.NR_CSEC_JAVA_HEAD_REQUEST.equals(headerKey)) {
                NewRelicSecurity.getAgent().getSecurityMetaData()
                        .addCustomAttribute(ICsecApiConstants.NR_CSEC_JAVA_HEAD_REQUEST, true);
            }

            String headerFullValue = EMPTY;
            List<String> headerElements = request.headers().getAll(headerKey);
            for (String headerValue : headerElements) {
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

    public static void processSecurityResponse(ChannelHandlerContext ctx, Object msg) {
        try {
            if (NewRelicSecurity.isHookProcessingActive() && msg instanceof FullHttpResponse) {
                SecurityMetaData securityMetaData = NewRelicSecurity.getAgent().getSecurityMetaData();
                com.newrelic.api.agent.security.schema.HttpResponse securityResponse =
                        securityMetaData.getResponse();
                processResponseHeaders((HttpResponse) msg, securityResponse);
                securityResponse.setResponseContentType(((FullHttpResponse) msg).headers().get(HttpHeaders.Names.CONTENT_TYPE));
                securityResponse.getResponseBody().append(((FullHttpResponse) msg).content().toString(StandardCharsets.UTF_8));
            }
        } catch (Throwable e) {
            NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(ERROR_PARSING_HTTP_RESPONSE_DATA, NETTY_4_0_0, e.getMessage()), e, NettyUtils.class.getName());
        }
    }

    public static void sendRXSSEvent(ChannelHandlerContext ctx, Object msg, String className, String methodName) {
        try {
            if (!NewRelicSecurity.isHookProcessingActive() || !(msg instanceof FullHttpResponse) || NewRelicSecurity.getAgent().getIastDetectionCategory().getRxssEnabled()) {
                return;
            }
            NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().setResponseCode(((FullHttpResponse) msg).getStatus().code());
            ServletHelper.executeBeforeExitingTransaction();
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
                NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.SECURITY_EXCEPTION_MESSAGE, NETTY_4_0_0, e.getMessage()), e, NettyUtils.class.getName());
                throw e;
            }
            NewRelicSecurity.getAgent().log(LogLevel.SEVERE, String.format(GenericHelper.ERROR_GENERATING_HTTP_REQUEST, NETTY_4_0_0, e.getMessage()), e, NettyUtils.class.getName());
            NewRelicSecurity.getAgent().reportIncident(LogLevel.SEVERE, String.format(GenericHelper.ERROR_GENERATING_HTTP_REQUEST, NETTY_4_0_0, e.getMessage()), e, NettyUtils.class.getName());
        }
    }

    private static void processResponseHeaders(HttpResponse response, com.newrelic.api.agent.security.schema.HttpResponse securityResponse) {
        for (Map.Entry<String, String> entry : response.headers().entries()) {
            String headerKey = entry.getKey().toLowerCase();
            String headerValue = entry.getValue();
            securityResponse.getHeaders().put(headerKey, headerValue);
        }
    }

    public static boolean isNettyLockAcquired(String operationLock) {
        try {
            return NewRelicSecurity.isHookProcessingActive() &&
                    Boolean.TRUE.equals(NewRelicSecurity.getAgent().getSecurityMetaData().getCustomAttribute(operationLock + Thread.currentThread().getId(), Boolean.class));
        } catch (Throwable ignored) {}
        return false;
    }

    public static boolean acquireNettyLockIfPossible(VulnerabilityCaseType reflectedXss, String operationLock) {
        return GenericHelper.acquireLockIfPossible(reflectedXss, operationLock+ Thread.currentThread().getId());
    }

    public static void releaseNettyLock(String operationLock) {
        GenericHelper.releaseLock(operationLock + Thread.currentThread().getId());
    }
}
