package com.newrelic.agent.security.instrumentation.grpc140;

import com.google.protobuf.Descriptors;
import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.*;
import com.newrelic.api.agent.security.schema.AgentMetaData;
import com.newrelic.api.agent.security.schema.HttpRequest;
import com.newrelic.api.agent.security.schema.SecurityMetaData;
import com.newrelic.api.agent.security.schema.exceptions.NewRelicSecurityException;
import com.newrelic.api.agent.security.schema.operation.RXSSOperation;
import com.newrelic.api.agent.security.schema.policy.AgentPolicy;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import io.grpc.Grpc;
import io.grpc.Metadata;
import io.grpc.ServerMethodDefinition;
import io.grpc.internal.ServerStream_Instrumentation;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class GrpcServerUtils {
    public static final String LIBRARY_NAME = "gRPC";
    private static final String X_FORWARDED_FOR = "x-forwarded-for";
    private static final String EMPTY = "";
    public static final String METHOD_NAME_START_CALL = "startCall";
    public static final String NR_SEC_CUSTOM_ATTRIB_NAME = "NR_CSEC_GRPC_SERVER_OPERATIONAL_LOCK_";
    private static Set<Descriptors.Descriptor> typeRegistries = new HashSet<>();

    public static <ReqT, ResT> void preprocessSecurityHook(ServerStream_Instrumentation call, ServerMethodDefinition<ReqT, ResT> methodDef, Metadata meta, String klass) {
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
                NewRelicSecurity.getAgent().log(LogLevel.SEVERE, e.getMessage(), e, GrpcServerUtils.class.getName());
                NewRelicSecurity.getAgent().reportIncident(LogLevel.SEVERE, e.getMessage(), e, GrpcServerUtils.class.getName());
            }

            AgentMetaData securityAgentMetaData = securityMetaData.getMetaData();

            securityRequest.setMethod(fullMethodName);
            String rawClientIP = call.getAttributes().get(Grpc.TRANSPORT_ATTR_REMOTE_ADDR).toString();
            // TODO: find server ip from request
            securityRequest.setClientIP(GrpcHelper.getFormattedIp(rawClientIP));
            securityRequest.setServerPort(Integer.parseInt(GrpcHelper.getPort(authority)));

            if (securityRequest.getClientIP() != null && !securityRequest.getClientIP().trim().isEmpty()) {
                securityAgentMetaData.getIps().add(securityRequest.getClientIP());
                securityRequest.setClientPort(GrpcHelper.getPort(rawClientIP));
            }

            processGRPCRequestMetadata(meta, securityRequest);

            securityMetaData.setTracingHeaderValue(getTraceHeader(securityRequest.getHeaders()));

            if (call.getAttributes().get(Grpc.TRANSPORT_ATTR_SSL_SESSION) != null) {
                securityRequest.setProtocol("https");
            } else {
                securityRequest.setProtocol("http");
            }

            securityRequest.setUrl(String.valueOf(uri));
            securityRequest.setIsGrpc(true);

            // TODO: Create OutBoundHttp data here : Skipping for now.
            securityRequest.setContentType(meta.get(Metadata.Key.of("content-type", Metadata.ASCII_STRING_MARSHALLER)));

            // TODO: moving this code to its proper place
            StackTraceElement[] trace = Thread.currentThread().getStackTrace();
            securityMetaData.getMetaData().setServiceTrace(Arrays.copyOfRange(trace, 2, trace.length));

            securityRequest.setRequestParsed(true);
            NewRelicSecurity.getAgent().getSecurityMetaData().getMetaData().addReflectedMetaData(GrpcHelper.REQUEST_TYPE,
                    String.valueOf(methodDef.getMethodDescriptor().getType()));
        } catch (Throwable e) {
            NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.ERROR_GENERATING_HTTP_REQUEST, GrpcUtils.GRPC_1_4_0, e.getMessage()), e, GrpcServerUtils.class.getName());
        }
    }

    public static void postProcessSecurityHook(Metadata metadata, int statusCode, String className, String methodName) {
        try {
            if (!NewRelicSecurity.isHookProcessingActive()) {
                return;
            }
            NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().setStatusCode(statusCode);

//            ServletHelper.executeBeforeExitingTransaction();
            //Add request URI hash to low severity event filter
            LowSeverityHelper.addRrequestUriToEventFilter(NewRelicSecurity.getAgent().getSecurityMetaData().getRequest());

            Set<String> headerNames = metadata.keys();
            for (String headerKey : headerNames) {
                NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().getHeaders().put(headerKey, metadata.get(Metadata.Key.of(headerKey, Metadata.ASCII_STRING_MARSHALLER)));
            }
            if (headerNames.contains("content-type")){
                NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().setContentType(metadata.get(Metadata.Key.of("content-type", Metadata.ASCII_STRING_MARSHALLER)));
            } else {
                NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().setContentType("application/grpc");
            }

            if(!ServletHelper.isResponseContentTypeExcluded(NewRelicSecurity.getAgent().getSecurityMetaData().getResponse().getResponseContentType())) {
                RXSSOperation rxssOperation = new RXSSOperation(NewRelicSecurity.getAgent().getSecurityMetaData().getRequest(),
                        NewRelicSecurity.getAgent().getSecurityMetaData().getResponse(),
                        className, methodName);
                NewRelicSecurity.getAgent().registerOperation(rxssOperation);
            }
            ServletHelper.tmpFileCleanUp(NewRelicSecurity.getAgent().getSecurityMetaData().getFuzzRequestIdentifier().getTempFiles());
        } catch (Throwable e) {
            if (e instanceof NewRelicSecurityException) {
                NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.SECURITY_EXCEPTION_MESSAGE, GrpcUtils.GRPC_1_4_0, e.getMessage()), e, GrpcServerUtils.class.getName());
                throw e;
            }
            NewRelicSecurity.getAgent().log(LogLevel.SEVERE, String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, GrpcUtils.GRPC_1_4_0, e.getMessage()), e, GrpcServerUtils.class.getName());
            NewRelicSecurity.getAgent().reportIncident(LogLevel.SEVERE, String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, GrpcUtils.GRPC_1_4_0, e.getMessage()), e, GrpcServerUtils.class.getName());
        }
    }


    public static void releaseLock() {
        try {
            if(NewRelicSecurity.isHookProcessingActive()) {
                NewRelicSecurity.getAgent().getSecurityMetaData().addCustomAttribute(getNrSecCustomAttrName(), null);
            }
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
            } else if (GenericHelper.CSEC_PARENT_ID.equals(headerKey)) {
                NewRelicSecurity.getAgent().getSecurityMetaData().addCustomAttribute(GenericHelper.CSEC_PARENT_ID, metadata.get(Metadata.Key.of(headerKey, Metadata.ASCII_STRING_MARSHALLER)));
            } else if (ICsecApiConstants.NR_CSEC_JAVA_HEAD_REQUEST.equals(headerKey)) {
                NewRelicSecurity.getAgent().getSecurityMetaData()
                        .addCustomAttribute(ICsecApiConstants.NR_CSEC_JAVA_HEAD_REQUEST, true);
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

    public static Descriptors.Descriptor getMessageTypeDescriptor(String messageClassName) {
        for (Descriptors.Descriptor descriptor : typeRegistries) {
            if (descriptor != null && messageClassName.equals(descriptor.getFullName())) {
                return descriptor;
            }
        }
        return null;
    }

    public static void addToTypeRegistries(Descriptors.Descriptor type) {
        typeRegistries.add(type);
    }
}
