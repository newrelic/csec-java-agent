package com.newrelic.agent.security.instrumentation.grpc1220.client;

import com.google.protobuf.Any;
import com.google.protobuf.Descriptors;
import com.google.protobuf.DynamicMessage;
import com.google.protobuf.InvalidProtocolBufferException;
import com.google.protobuf.Message;
import com.google.protobuf.util.JsonFormat;
import com.newrelic.agent.security.instrumentation.grpc1220.GrpcServerUtils;
import com.newrelic.api.agent.security.instrumentation.helpers.GrpcClientRequestReplayHelper;
import com.newrelic.api.agent.security.instrumentation.helpers.GrpcHelper;
import com.newrelic.api.agent.security.schema.ControlCommandDto;
import com.newrelic.api.agent.security.schema.FuzzRequestBean;
import com.newrelic.api.agent.security.schema.StringUtils;
import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;
import io.grpc.Metadata;
import io.grpc.netty.GrpcSslContexts;
import io.grpc.netty.NettyChannelBuilder;
import io.grpc.stub.MetadataUtils;
import io.grpc.stub.StreamObserver;

import javax.net.ssl.SSLException;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
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

    private final X509TrustManager x509TrustManager = new X509TrustManager() {
        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType)
                throws CertificateException {
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType)
                throws CertificateException {
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[] {};
        }
    };

    // Create a trust manager that does not validate certificate chains
    private final TrustManager[] trustAllCerts = new TrustManager[]{
            x509TrustManager
    };

    private final ThreadLocal<ManagedChannel> clientThreadLocal = new ThreadLocal<ManagedChannel>() {
        @Override
        protected ManagedChannel initialValue() {
            ManagedChannel channel = null;
            try {
                channel = isSecure?getManagedChannelWithSsl("localhost", serverPort):getManagedChannelWithoutSsl("localhost", serverPort);
//                System.out.printf("Client initialised for port :: %s", serverPort);
            } catch (Exception e) {
                e.printStackTrace();
            }
            return channel;
        }
    };

    public Object fireRequest(ControlCommandDto controlCommandDto, int repeatCount) {
        try {
            FuzzRequestBean requestBean = controlCommandDto.getRequestBean();
            List<String> payloads = controlCommandDto.getRequestPayloads();
            serverPort = requestBean.getServerPort();
            isSecure = StringUtils.equals("https", requestBean.getProtocol());
            ManagedChannel channel = clientThreadLocal.get();

//            System.out.println(String.format(FIRING_REQUEST_METHOD_S, requestBean.getMethod()));
//            System.out.println(String.format(FIRING_REQUEST_URL_S, requestBean.getUrl()));
//            System.out.println(String.format(FIRING_REQUEST_HEADERS_S, requestBean.getHeaders()));

            Object isSuccess = false;
            switch (requestBean.getReflectedMetaData().get(GrpcHelper.REQUEST_TYPE)){
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
        } catch (Throwable ex){
            // TODO: send critical log message
            if(repeatCount >= 0){
                return fireRequest(controlCommandDto, --repeatCount);
            }
            return false;
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
        GrpcStubs.CustomStub stub = GrpcStubs.newBlockingStub(channel);

//            StringBuilder body = requestBean.getBody();
//            String requestData = String.valueOf(body.deleteCharAt(body.length()-1).deleteCharAt(0));
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
                        .unaryCall(pack, serviceName, methodName, getMessageDescriptor(requestClass));
//                    System.out.println(String.format(REQUEST_SUCCESS_S_RESPONSE_S_S, requestBean, response, response.toString()));
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
//                System.out.println(String.format(REQUEST_SUCCESS_S_RESPONSE_S_S, requestBean, response, response.toString()));
            }

            @Override
            public void onError(Throwable throwable) {

            }

            @Override
            public void onCompleted() {

            }
        };

        GrpcStubs.CustomStub stub = GrpcStubs.newStub(channel);
//            StringBuilder body = requestBean.getBody();
//            String requestData = String.valueOf(body.deleteCharAt(body.length()-1).deleteCharAt(0));
        String[] methodSplitData = requestBean.getMethod().split("/");
        String serviceName = methodSplitData[0];
        String methodName = methodSplitData[1];
        String requestClass = requestBean.getReflectedMetaData().get(GrpcHelper.NR_SEC_GRPC_REQUEST_DATA_TYPE);

        Metadata headers = new Metadata();
        for (Map.Entry<String, String> header : requestBean.getHeaders().entrySet()) {
            headers.put(Metadata.Key.of(header.getKey(), Metadata.ASCII_STRING_MARSHALLER), header.getValue());
        }
        StreamObserver<Any> requestObserver = stub.withInterceptors(MetadataUtils.newAttachHeadersInterceptor(headers)).clientStream(responseObserver, serviceName, methodName, getMessageDescriptor(requestClass));

        for (String requestData : payloads) {
            try {
//                System.out.println(requestData);
                Any pack = getMessageOfTypeAny(requestData, requestClass);
                requestObserver.onNext(pack);
            } catch (Throwable e) {
                return e;
//                    GrpcClientRequestReplayHelper.getInstance().addFuzzFailEventToQueue(requestBean, e);
            }
        }
        Thread.sleep(100);
        requestObserver.onCompleted();
        return null;
    }

    private static Object customServerStream(ManagedChannel channel, FuzzRequestBean requestBean, List<String> payloads) {
        GrpcStubs.CustomStub stub = GrpcStubs.newBlockingStub(channel);
//            StringBuilder body = requestBean.getBody();
//            String requestData = String.valueOf(body.deleteCharAt(body.length()-1).deleteCharAt(0));
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
                Iterator<Any> response = stub.withInterceptors(MetadataUtils.newAttachHeadersInterceptor(headers))
                        .serverStream(pack, serviceName, methodName, getMessageDescriptor(requestClass));
                while (response.hasNext()) {
//                    System.out.println(String.format(REQUEST_SUCCESS_S_RESPONSE_S_S, requestBean, response, response.toString()));
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
//        String requestData = String.valueOf(body.deleteCharAt(body.length()-1).deleteCharAt(0));
        String[] methodSplitData = requestBean.getMethod().split("/");
        String serviceName = methodSplitData[0];
        String methodName = methodSplitData[1];
        String requestClass = requestBean.getReflectedMetaData().get(GrpcHelper.NR_SEC_GRPC_REQUEST_DATA_TYPE);

        StreamObserver<Any> responseObserver = new StreamObserver<Any>() {
            @Override
            public void onNext(Any response) {
//                System.out.println(String.format(REQUEST_SUCCESS_S_RESPONSE_S_S, requestBean, response, response.toString()));
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
                .biDiStream(responseObserver, serviceName, methodName, getMessageDescriptor(requestClass));

        for (String requestData : payloads) {
            try{
                Any pack = getMessageOfTypeAny(requestData, requestClass);
                requestObserver.onNext(pack);
            } catch (Throwable e) {
                return e;
//                    GrpcClientRequestReplayHelper.getInstance().addFuzzFailEventToQueue(requestBean, e);
            }
        }

        Thread.sleep(100);
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

//    private static Descriptors.Descriptor getMessageDescriptor(String messageClassName) {
//        Descriptors.Descriptor descriptor = null;
//
//        try {
//            Class<?> messageClass = getRequestClassRef(messageClassName);
//            Method getDescriptorMethod = messageClass.getMethod("getDescriptor");
//            descriptor = (Descriptors.Descriptor) getDescriptorMethod.invoke(null);
//        } catch (Throwable ignored) {
//        }
//        return descriptor;
//    }
//
//    private static Class<?> getRequestClassRef(String messageClassName) {
//        for (Class<?> aClass : NewRelicSecurity.getAgent().getInstrumentation().getAllLoadedClasses()) {
//            if (aClass.getName().equals(messageClassName)){
//                return aClass;
//            }
//        }
//        return null;
//    }

    private ManagedChannel getManagedChannelWithSsl(String host, int port) throws SSLException {
        return NettyChannelBuilder.forAddress(host, port)
                .sslContext(
                        GrpcSslContexts.forClient()
                                .trustManager((X509Certificate) x509TrustManager)
                                .build()
                )
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