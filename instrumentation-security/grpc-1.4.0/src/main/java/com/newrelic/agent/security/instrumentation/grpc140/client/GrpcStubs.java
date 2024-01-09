package com.newrelic.agent.security.instrumentation.grpc140.client;

import com.google.protobuf.Any;
import com.google.protobuf.Descriptors;
import io.grpc.CallOptions;
import io.grpc.Channel;
import io.grpc.MethodDescriptor;
import io.grpc.stub.StreamObserver;

import java.util.Iterator;

import static io.grpc.MethodDescriptor.generateFullMethodName;

public class GrpcStubs {
    public static final class CustomStub extends io.grpc.stub.AbstractStub<CustomStub> {

        private CustomStub(Channel channel) {
            super(channel);
        }

        private CustomStub(
                Channel channel, CallOptions callOptions) {
            super(channel, callOptions);
        }

        @Override
        protected CustomStub build(Channel channel, CallOptions callOptions) {
            return new CustomStub(channel, callOptions);
        }

        public Any unaryCall(Any request, String serviceName, String methodName) {
            return io.grpc.stub.ClientCalls.blockingUnaryCall(
                    getChannel(), getSimpleMethod(serviceName, methodName), getCallOptions(), request);
        }

        public Iterator<Any> serverStream(Any request, String serviceName, String methodName) {
            return io.grpc.stub.ClientCalls.blockingServerStreamingCall(
                    getChannel(), getServerStreamMethod(serviceName, methodName), getCallOptions(), request);
        }

        public StreamObserver<Any> clientStream(StreamObserver<Any> responseObserver, String serviceName, String methodName) {
            return io.grpc.stub.ClientCalls.asyncClientStreamingCall(
                    getChannel().newCall(getClientStreamMethod(serviceName, methodName), getCallOptions()), responseObserver);
        }

        public StreamObserver<Any> biDiStream(StreamObserver<Any> responseObserver, String serviceName, String methodName) {
            return io.grpc.stub.ClientCalls.asyncBidiStreamingCall(
                    getChannel().newCall(getBiDiMethod(serviceName, methodName), getCallOptions()), responseObserver);
        }
    }

    public static MethodDescriptor<Any, Any> getSimpleMethod(String serviceName, String methodName) {
        MethodDescriptor<Any, Any> getMethod;
        synchronized (GrpcStubs.class) {
            getMethod = MethodDescriptor.<Any, Any>newBuilder()
                            .setType(MethodDescriptor.MethodType.UNARY)
                            .setFullMethodName(generateFullMethodName(serviceName, methodName))
                            .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(Any.getDefaultInstance()))
                            .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(Any.getDefaultInstance()))
                            .build();
        }
        return getMethod;
    }

    public static MethodDescriptor<Any, Any> getServerStreamMethod(String serviceName, String methodName) {
        MethodDescriptor<Any, Any> getMethod;
        synchronized (GrpcStubs.class) {
            getMethod = MethodDescriptor.<Any, Any>newBuilder()
                            .setType(MethodDescriptor.MethodType.SERVER_STREAMING)
                            .setFullMethodName(generateFullMethodName(serviceName, methodName))
                            .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(Any.getDefaultInstance()))
                            .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(Any.getDefaultInstance()))
                            .build();
        }
        return getMethod;
    }

    public static MethodDescriptor<Any, Any> getClientStreamMethod(String serviceName, String methodName) {
        MethodDescriptor<Any, Any> getMethod;
        synchronized (GrpcStubs.class) {
            getMethod = MethodDescriptor.<Any, Any>newBuilder()
                            .setType(MethodDescriptor.MethodType.CLIENT_STREAMING)
                            .setFullMethodName(generateFullMethodName(serviceName, methodName))
                            .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(Any.getDefaultInstance()))
                            .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(Any.getDefaultInstance()))
                            .build();
        }
        return getMethod;
    }

    public static MethodDescriptor<Any, Any> getBiDiMethod(String serviceName, String methodName) {
        MethodDescriptor<Any, Any> getMethod;
        synchronized (GrpcStubs.class) {
            getMethod = MethodDescriptor.<Any, Any>newBuilder()
                            .setType(MethodDescriptor.MethodType.BIDI_STREAMING)
                            .setFullMethodName(generateFullMethodName(serviceName, methodName))
                            .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(Any.getDefaultInstance()))
                            .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(Any.getDefaultInstance()))
                            .build();
        }
        return getMethod;
    }

    public static CustomStub newBlockingStub(Channel channel) {
        return new CustomStub(channel);
    }

    public static CustomStub newStub(Channel channel) {
        return new CustomStub(channel);
    }
}
