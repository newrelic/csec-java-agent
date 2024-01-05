package com.newrelic.agent.security.instrumentation.grpc140;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GrpcHelper;
import com.newrelic.api.agent.security.instrumentation.helpers.LowSeverityHelper;
import com.newrelic.api.agent.security.instrumentation.helpers.ServletHelper;
import com.newrelic.api.agent.security.schema.AgentMetaData;
import com.newrelic.api.agent.security.schema.HttpRequest;
import com.newrelic.api.agent.security.schema.SecurityMetaData;
import com.newrelic.api.agent.security.schema.exceptions.NewRelicSecurityException;
import com.newrelic.api.agent.security.schema.operation.RXSSOperation;
import com.newrelic.api.agent.security.schema.policy.AgentPolicy;
import io.grpc.Attributes;
import io.grpc.Grpc;
import io.grpc.Metadata;
import io.grpc.SecurityLevel;
import io.grpc.ServerMethodDefinition;
import io.grpc.internal.ServerStream;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Map;
import java.util.Set;

public class GrpcServerUtils {
    private static final String X_FORWARDED_FOR = "x-forwarded-for";
    private static final String EMPTY = "";
    public static final String METHOD_NAME_START_CALL = "startCall";
    public static final String NR_SEC_CUSTOM_ATTRIB_NAME = "NR_CSEC_GRPC_SERVER_OPERATIONAL_LOCK_";

    public static <ReqT, ResT> void preprocessSecurityHook(ServerStream call, ServerMethodDefinition<ReqT, ResT> methodDef, Metadata meta, String klass) {
        try {
            if (!NewRelicSecurity.isHookProcessingActive()) {
                return;
            }
            SecurityMetaData securityMetaData = NewRelicSecurity.getAgent().getSecurityMetaData();

            HttpRequest securityRequest = securityMetaData.getRequest();
            if (securityRequest.isRequestParsed()) {
                return;
            }

            URI uri = null;
            String authority = call.getAuthority();
            String fullMethodName = methodDef.getMethodDescriptor().getFullMethodName();
            try {
                uri = new URI("grpc", authority, "/" + fullMethodName, null, null);
            } catch (URISyntaxException e) {
                e.printStackTrace(); // intentionally added to notify the uri error
            }

            AgentMetaData securityAgentMetaData = securityMetaData.getMetaData();

            securityRequest.setMethod(fullMethodName);
            String rawClientIP = call.getAttributes().get(Grpc.TRANSPORT_ATTR_REMOTE_ADDR).toString();
            securityRequest.setClientIP(GrpcHelper.getFormattedIp(rawClientIP));
            securityRequest.setServerPort(Integer.parseInt(GrpcHelper.getPort(authority)));

            if (securityRequest.getClientIP() != null && !securityRequest.getClientIP().trim().isEmpty()) {
                securityAgentMetaData.getIps().add(securityRequest.getClientIP());
                securityRequest.setClientPort(GrpcHelper.getPort(rawClientIP));
            }

            processGRPCRequestMetadata(meta, securityRequest);

            securityMetaData.setTracingHeaderValue(getTraceHeader(securityRequest.getHeaders()));

            for (Attributes.Key o : call.getAttributes().keys()) {
                if ("io.grpc.internal.GrpcAttributes.securityLevel".equals(o.toString()) ||
                        "io.grpc.CallCredentials.securityLevel".equals(o.toString()))
                    if (call.getAttributes().get(o) == SecurityLevel.NONE) {
                        securityRequest.setProtocol("http");
                        break;
                    } else if (call.getAttributes().get(o) == SecurityLevel.INTEGRITY || call.getAttributes().get(o) == SecurityLevel.PRIVACY_AND_INTEGRITY) {
                        securityRequest.setProtocol("https");
                        break;
                    }
            }

            securityRequest.setUrl(String.valueOf(uri));
            securityRequest.setIsGrpc(true);

            // TODO: Create OutBoundHttp data here : Skipping for now.
            securityRequest.setContentType(meta.get(Metadata.Key.of("content-type", Metadata.ASCII_STRING_MARSHALLER)));

            securityAgentMetaData.setServiceTrace(Thread.currentThread().getStackTrace());
            securityRequest.setRequestParsed(true);
        } catch (Throwable ignored) {
        }
    }

    public static void postProcessSecurityHook(Metadata metadata, String className, String methodName) {
        try {
            if (!NewRelicSecurity.isHookProcessingActive()) {
                return;
            }
            //Add request URI hash to low severity event filter
            LowSeverityHelper.addRrequestUriToEventFilter(NewRelicSecurity.getAgent().getSecurityMetaData().getRequest());

            Set<String> headerNames = metadata.keys();
            for (String headerKey : headerNames) {
                NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().getHeaders().put(headerKey, metadata.get(Metadata.Key.of(headerKey, Metadata.ASCII_STRING_MARSHALLER)));
            }

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


    public static void releaseLock() {
        try {
            try {
                if(NewRelicSecurity.isHookProcessingActive()) {
                    NewRelicSecurity.getAgent().getSecurityMetaData().addCustomAttribute(getNrSecCustomAttrName(), null);
                }
            } catch (Throwable ignored){}
        } catch (Throwable ignored) {
        }
    }

    private static String getNrSecCustomAttrName() {
        return GrpcServerUtils.NR_SEC_CUSTOM_ATTRIB_NAME+Thread.currentThread().getId();
    }

    public static boolean acquireLockIfPossible() {
        try {
            if (NewRelicSecurity.isHookProcessingActive() &&
                    !isLockAcquired(getNrSecCustomAttrName())) {
                NewRelicSecurity.getAgent().getSecurityMetaData().addCustomAttribute(getNrSecCustomAttrName(), true);
                return true;
            }
        } catch (Throwable ignored){}
        return false;
    }

    private static boolean isLockAcquired(String nrSecCustomAttrName) {
        try {
            return NewRelicSecurity.isHookProcessingActive() &&
                    Boolean.TRUE.equals(NewRelicSecurity.getAgent().getSecurityMetaData().getCustomAttribute(nrSecCustomAttrName, Boolean.class));
        } catch (Throwable ignored) {}
        return false;
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

    public static void processGRPCRequestMetadata(Metadata metadata, HttpRequest securityRequest) {
        Set<String> headerNames = metadata.keys();
        for (String headerKey : headerNames) {
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
                NewRelicSecurity.getAgent().getSecurityMetaData().setFuzzRequestIdentifier(ServletHelper.parseFuzzRequestIdentifierHeader(metadata.get(Metadata.Key.of(headerKey, Metadata.ASCII_STRING_MARSHALLER))));
            }
            String headerFullValue = EMPTY;
            String[] headerElements = metadata.get(Metadata.Key.of(headerKey, Metadata.ASCII_STRING_MARSHALLER)).split(";");
            for (String headerValue : headerElements) {
                if (headerValue != null && !headerValue.trim().isEmpty()) {
                    if (takeNextValue) {
                        agentMetaData.setClientDetectedFromXFF(true);
                        securityRequest.setClientIP(headerValue);
                        agentMetaData.getIps().add(securityRequest.getClientIP());
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
}
