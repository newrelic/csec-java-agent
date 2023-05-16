package security.io.netty400.utils;

import com.newrelic.api.agent.NewRelic;
import com.newrelic.api.agent.Transaction;
import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.LowSeverityHelper;
import com.newrelic.api.agent.security.instrumentation.helpers.ServletHelper;
import com.newrelic.api.agent.security.schema.AgentMetaData;
import com.newrelic.api.agent.security.schema.SecurityMetaData;
import com.newrelic.api.agent.security.schema.StringUtils;
import com.newrelic.api.agent.security.schema.exceptions.NewRelicSecurityException;
import com.newrelic.api.agent.security.schema.operation.RXSSOperation;
import com.newrelic.api.agent.security.schema.policy.AgentPolicy;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.http.FullHttpResponse;
import io.netty.handler.codec.http.HttpContent;
import io.netty.handler.codec.http.HttpRequest;
import io.netty.handler.codec.http.HttpResponse;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class NettyUtils {
    public static String NR_SEC_CUSTOM_ATTRIB_NAME = "NETTY-4.8-REQ-BODY-TRACKER";
    private static final String X_FORWARDED_FOR = "x-forwarded-for";
    private static final String EMPTY = "";
    public static final String WRITE_METHOD_NAME = "write";

    public static final String IO_NETTY = "io.netty.";

    public static void processSecurityRequest(ChannelHandlerContext ctx, Object msg, String className) {
        try {
            Transaction tx = NewRelic.getAgent().getTransaction();
            Object secMetaObj = tx.getSecurityMetaData();
            if (msg instanceof HttpRequest) {
                if (!(secMetaObj instanceof SecurityMetaData) ||
                        NewRelicSecurity.getAgent().getSecurityMetaData() == null) {
                    return;
                }
                SecurityMetaData securityMetaData = NewRelicSecurity.getAgent().getSecurityMetaData();
                com.newrelic.api.agent.security.schema.HttpRequest securityRequest =
                        securityMetaData.getRequest();

                if (!NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty() && securityRequest.isRequestParsed()) {
                    return;
                }
                securityRequest.setMethod(((HttpRequest) msg).getMethod().name());
                securityRequest.setUrl(((HttpRequest) msg).getUri());
                setClientAddressDetails(securityMetaData, ctx.channel().remoteAddress().toString());
                setServerPortDetails(securityRequest, ctx.channel().localAddress().toString());
                processHttpRequestHeader((HttpRequest)msg, securityRequest);
                securityMetaData.setTracingHeaderValue(getTraceHeader(securityRequest.getHeaders()));

                securityRequest.setProtocol(((HttpRequest) msg).getProtocolVersion().protocolName());
                securityRequest.setContentType(securityRequest.getHeaders().get("content-type"));
                StackTraceElement[] stack = Thread.currentThread().getStackTrace();
                securityMetaData.getMetaData().setServiceTrace(Arrays.copyOfRange(stack, 1, stack.length));
                securityRequest.setRequestParsed(true);
            } else if (msg instanceof HttpContent) {
                if (!(secMetaObj instanceof SecurityMetaData) ||
                        NewRelicSecurity.getAgent().getSecurityMetaData() == null) {
                    return;
                }
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
            ignored.printStackTrace();
        }
    }

    private static void setServerPortDetails(com.newrelic.api.agent.security.schema.HttpRequest securityRequest, String address) {
        try {
            String port = StringUtils.substringAfterLast(address, ":");
            if (StringUtils.isBlank(port)) {
                return;
            }
            securityRequest.setServerPort(Integer.parseInt(port));
        } catch (Throwable throwable) {}
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
            Transaction tx = NewRelic.getAgent().getTransaction();
            Object secMetaObj = tx.getSecurityMetaData();
            if (msg instanceof FullHttpResponse) {
                if (!(secMetaObj instanceof SecurityMetaData) ||
                        NewRelicSecurity.getAgent().getSecurityMetaData() == null) {
                    return;
                }
                SecurityMetaData securityMetaData = NewRelicSecurity.getAgent().getSecurityMetaData();
                com.newrelic.api.agent.security.schema.HttpResponse securityResponse =
                        securityMetaData.getResponse();
                processResponseHeaders((HttpResponse) msg, securityResponse);
                securityResponse.setResponseContentType(((FullHttpResponse) msg).headers().get("content-type"));
                securityResponse.getResponseBody().append(((FullHttpResponse) msg).content().toString(StandardCharsets.UTF_8));
            }
        } catch (Throwable e) {
            e.printStackTrace();
        }
    }

    public static void sendRXSSEvent(ChannelHandlerContext ctx, Object msg, String className, String methodName) {
        try {
            if (!NewRelicSecurity.isHookProcessingActive() || !(msg instanceof FullHttpResponse)) {
                return;
            }
            //Add request URI hash to low severity event filter
            LowSeverityHelper.addRrequestUriToEventFilter(NewRelicSecurity.getAgent().getSecurityMetaData().getRequest());

            RXSSOperation rxssOperation = new RXSSOperation(NewRelicSecurity.getAgent().getSecurityMetaData().getRequest(),
                    NewRelicSecurity.getAgent().getSecurityMetaData().getResponse(),
                    className, methodName);
            NewRelicSecurity.getAgent().registerOperation(rxssOperation);

        } catch (Throwable e) {
            if (e instanceof NewRelicSecurityException) {
                e.printStackTrace();
                throw e;
            }
        }
    }

    private static void processResponseHeaders(HttpResponse response, com.newrelic.api.agent.security.schema.HttpResponse securityResponse) {
        for (Map.Entry<String, String> entry : response.headers().entries()) {
            String headerKey = entry.getKey().toLowerCase();
            String headerValue = entry.getValue();
            securityResponse.getHeaders().put(headerKey, headerValue);
        }
    }
}
