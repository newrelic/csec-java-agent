package com.newrelic.agent.security.instrumentation.grpc1400.client;

import com.google.protobuf.Any;
import com.google.protobuf.Descriptors;
import com.google.protobuf.DynamicMessage;
import com.google.protobuf.InvalidProtocolBufferException;
import com.google.protobuf.Message;
import com.google.protobuf.util.JsonFormat;
import com.newrelic.agent.security.instrumentation.grpc1400.GrpcServerUtils;
import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GrpcHelper;
import com.newrelic.api.agent.security.schema.ControlCommandDto;
import com.newrelic.api.agent.security.schema.FuzzRequestBean;
import com.newrelic.api.agent.security.schema.StringUtils;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import io.grpc.ChannelCredentials;
import io.grpc.Grpc;
import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;
import io.grpc.Metadata;
import io.grpc.TlsChannelCredentials;
import io.grpc.stub.MetadataUtils;
import io.grpc.stub.StreamObserver;
import io.netty.handler.ssl.util.InsecureTrustManagerFactory;

import javax.net.ssl.SSLException;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

public class GrpcClient {
    public static final String REQUEST_SUCCESS_S_RESPONSE_S_S = "Request success : %s :: response : %s : %s";
    public static final String CALL_FAILED_REQUEST_S_REASON = "Call failed : request %s reason : ";
    public static final String FIRING_REQUEST_METHOD_S = "Firing request :: Method : %s";
    public static final String FIRING_REQUEST_URL_S = "Firing request :: URL : %s";
    public static final String FIRING_REQUEST_HEADERS_S = "Firing request :: Headers : %s";
    public static int serverPort;
    private static Boolean isSecure = false;
    private static final Object lock = new Object();
    private boolean isConnected = true;
    private final String unary = "UNARY";
    private final String client_streaming = "CLIENT_STREAMING";
    private final String server_streaming = "SERVER_STREAMING";
    private final String bidi_streaming = "BIDI_STREAMING";

    private final ThreadLocal<ManagedChannel> clientThreadLocal = new ThreadLocal<ManagedChannel>() {
        @Override
        protected ManagedChannel initialValue() {
            ManagedChannel channel = null;
            try {
                channel = isSecure?getManagedChannelWithSsl("localhost", serverPort):getManagedChannelWithoutSsl("localhost", serverPort);
            } catch (Exception e) {
                NewRelicSecurity.getAgent().log(LogLevel.SEVERE, String.format("gRPC Client initialisation failed for port %d.", serverPort), e, GrpcClient.class.getName());
            }
            return channel;
        }
    };

    public Object fireRequest(ControlCommandDto controlCommandDto, int repeatCount) {
        FuzzRequestBean requestBean = null;
        try {
            requestBean = controlCommandDto.getRequestBean();
            List<String> payloads = controlCommandDto.getRequestPayloads();
            serverPort = requestBean.getServerPort();
            isSecure = StringUtils.equals("https", requestBean.getProtocol());
            ManagedChannel channel = clientThreadLocal.get();

            NewRelicSecurity.getAgent().log(LogLevel.FINER, String.format(FIRING_REQUEST_METHOD_S, requestBean.getMethod()), GrpcClient.class.getName());
            NewRelicSecurity.getAgent().log(LogLevel.FINER, String.format(FIRING_REQUEST_URL_S, requestBean.getUrl()), GrpcClient.class.getName());
            NewRelicSecurity.getAgent().log(LogLevel.FINER, String.format(FIRING_REQUEST_HEADERS_S, requestBean.getHeaders()), GrpcClient.class.getName());

            Object isSuccess = false;
            switch (requestBean.getReflectedMetaData().get(GrpcHelper.REQUEST_TYPE)) {
                case unary:
                    isSuccess = customUnaryCall(channel, requestBean, payloads);
                    break;
                case client_streaming:
                    isSuccess = customClientStream(channel, requestBean, payloads);
                    break;
                case server_streaming:
                    isSuccess = customServerStream(channel, requestBean, payloads);
                    break;
                case bidi_streaming:
                    isSuccess = customBiDiStream(channel, requestBean, payloads);
                    break;
            }
            return isSuccess;
        } catch (InterruptedException e) {
            if (repeatCount >= 0) {
                return fireRequest(controlCommandDto, --repeatCount);
            }
            return false;
        } catch (Throwable e) {
            return e;
        }
    }

    private static final class InstanceHolder {
        static final GrpcClient instance = new GrpcClient();
    }

    public static GrpcClient getInstance() {
        synchronized (lock) {
            return InstanceHolder.instance;
        }
    }

    private Object customUnaryCall(ManagedChannel channel, FuzzRequestBean requestBean, List<String> payloads) {
        GrpcStubs.CustomStub stub = GrpcStubs.newStub(channel);
        String[] methodSplitData = requestBean.getMethod().split("/");
        String serviceName = methodSplitData[0];
        String methodName = methodSplitData[1];
        String requestClass = requestBean.getReflectedMetaData().get(GrpcHelper.NR_SEC_GRPC_REQUEST_DATA_TYPE);

        Metadata headers = new Metadata();
        for (Map.Entry<String, String> header : requestBean.getHeaders().entrySet()) {
            headers.put(Metadata.Key.of(header.getKey(), Metadata.ASCII_STRING_MARSHALLER), header.getValue());
        }

        for (String requestData : payloads) {
            try {
                Any pack = getMessageOfTypeAny(requestData, requestClass);
                Any response = stub.withInterceptors(MetadataUtils.newAttachHeadersInterceptor(headers))
                        .unaryCall(pack, serviceName, methodName);
                NewRelicSecurity.getAgent().log(LogLevel.FINER, String.format(REQUEST_SUCCESS_S_RESPONSE_S_S, requestBean, response, response.toString()), GrpcClient.class.getName());
            } catch (Throwable e) {
                return e;
//                    GrpcClientRequestReplayHelper.getInstance().addFuzzFailEventToQueue(requestBean, e);
            }
        }
        return null;
    }

    private static Object customClientStream(ManagedChannel channel, FuzzRequestBean requestBean, List<String> payloads) throws InterruptedException {
        StreamObserver<Any> responseObserver = new StreamObserver<Any>() {

            @Override
            public void onNext(Any response) {
                NewRelicSecurity.getAgent().log(LogLevel.FINER, String.format(REQUEST_SUCCESS_S_RESPONSE_S_S, requestBean, response, response.toString()), GrpcClient.class.getName());
            }

            @Override
            public void onError(Throwable throwable) {

            }

            @Override
            public void onCompleted() {

            }
        };

        GrpcStubs.CustomStub stub = GrpcStubs.newStub(channel);
        String[] methodSplitData = requestBean.getMethod().split("/");
        String serviceName = methodSplitData[0];
        String methodName = methodSplitData[1];
        String requestClass = requestBean.getReflectedMetaData().get(GrpcHelper.NR_SEC_GRPC_REQUEST_DATA_TYPE);

        Metadata headers = new Metadata();
        for (Map.Entry<String, String> header : requestBean.getHeaders().entrySet()) {
            headers.put(Metadata.Key.of(header.getKey(), Metadata.ASCII_STRING_MARSHALLER), header.getValue());
        }
        StreamObserver<Any> requestObserver = stub.withInterceptors(MetadataUtils.newAttachHeadersInterceptor(headers)).clientStream(responseObserver, serviceName, methodName);

        for (String requestData : payloads) {
            try {
                Any pack = getMessageOfTypeAny(requestData, requestClass);
                requestObserver.onNext(pack);
            } catch (Throwable e) {
                return e;
//                    GrpcClientRequestReplayHelper.getInstance().addFuzzFailEventToQueue(requestBean, e);
            }
        }
        requestObserver.onCompleted();
        return null;
    }

    private static Object customServerStream(ManagedChannel channel, FuzzRequestBean requestBean, List<String> payloads) {
        GrpcStubs.CustomStub stub = GrpcStubs.newBlockingStub(channel);
        String[] methodSplitData = requestBean.getMethod().split("/");
        String serviceName = methodSplitData[0];
        String methodName = methodSplitData[1];
        String requestClass = requestBean.getReflectedMetaData().get(GrpcHelper.NR_SEC_GRPC_REQUEST_DATA_TYPE);

        Metadata headers = new Metadata();
        for (Map.Entry<String, String> header : requestBean.getHeaders().entrySet()) {
            headers.put(Metadata.Key.of(header.getKey(), Metadata.ASCII_STRING_MARSHALLER), header.getValue());
        }

        for (String requestData : payloads) {
            try {
                Any pack = getMessageOfTypeAny(requestData, requestClass);
                Iterator<Any> responses = stub.withInterceptors(MetadataUtils.newAttachHeadersInterceptor(headers))
                        .serverStream(pack, serviceName, methodName);
                while (responses.hasNext()) {
                    Any response = responses.next();
                    NewRelicSecurity.getAgent().log(LogLevel.FINER, String.format(REQUEST_SUCCESS_S_RESPONSE_S_S, requestBean, response, response.toString()), GrpcClient.class.getName());
                }
            } catch (Throwable e) {
                return e;
//                    GrpcClientRequestReplayHelper.getInstance().addFuzzFailEventToQueue(requestBean, e);
            }
        }
        return null;
    }

    public static Object customBiDiStream(ManagedChannel channel, FuzzRequestBean requestBean, List<String> payloads) throws InterruptedException {
        GrpcStubs.CustomStub stub = GrpcStubs.newStub(channel);
        StringBuilder body = requestBean.getBody();
        String[] methodSplitData = requestBean.getMethod().split("/");
        String serviceName = methodSplitData[0];
        String methodName = methodSplitData[1];
        String requestClass = requestBean.getReflectedMetaData().get(GrpcHelper.NR_SEC_GRPC_REQUEST_DATA_TYPE);

        StreamObserver<Any> responseObserver = new StreamObserver<Any>() {
            @Override
            public void onNext(Any response) {
                NewRelicSecurity.getAgent().log(LogLevel.FINER, String.format(REQUEST_SUCCESS_S_RESPONSE_S_S, requestBean, response, response.toString()), GrpcClient.class.getName());
            }

            @Override
            public void onError(Throwable t) {

            }

            @Override
            public void onCompleted() {

            }
        };

        Metadata headers = new Metadata();
        for (Map.Entry<String, String> header : requestBean.getHeaders().entrySet()) {
            headers.put(Metadata.Key.of(header.getKey(), Metadata.ASCII_STRING_MARSHALLER), header.getValue());
        }
        StreamObserver<Any> requestObserver = stub.withInterceptors(MetadataUtils.newAttachHeadersInterceptor(headers))
                .biDiStream(responseObserver, serviceName, methodName);

        for (String requestData : payloads) {
            try{
                Any pack = getMessageOfTypeAny(requestData, requestClass);
                requestObserver.onNext(pack);
            } catch (Throwable e) {
                return e;
//                    GrpcClientRequestReplayHelper.getInstance().addFuzzFailEventToQueue(requestBean, e);
            }
        }
        requestObserver.onCompleted();
        return null;
    }


    private static Any getMessageOfTypeAny(String s, String requestType) {
        Message.Builder messageBuilder = DynamicMessage.newBuilder(getMessageDescriptor(requestType));
        Any pack = null;
        try {
            JsonFormat.parser().merge(s, messageBuilder);
            Message build = messageBuilder.build();
            pack = Any.parseFrom(build.toByteString());
        } catch (InvalidProtocolBufferException ignored) {
        }
        return pack;
    }

    private static Descriptors.Descriptor getMessageDescriptor(String messageClassName) {
        return GrpcServerUtils.getMessageTypeDescriptor(messageClassName);
    }

    private ManagedChannel getManagedChannelWithSsl(String host, int port) throws SSLException {
        ChannelCredentials creds;
        creds = TlsChannelCredentials.newBuilder()
                .trustManager(InsecureTrustManagerFactory.INSTANCE.getTrustManagers())
                .build();

        return Grpc.newChannelBuilder(String.format("%s:%s", host, port), creds)
                .build();
    }

    private static ManagedChannel getManagedChannelWithoutSsl(String host, int port) {
        return ManagedChannelBuilder
                .forTarget(String.format("%s:%s", host, port))
                .usePlaintext()
                .build();
    }

    public boolean isConnected() {
        return isConnected;
    }

    public void setConnected(boolean connected) {
        isConnected = connected;
    }
}