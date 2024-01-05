package com.newrelic.agent.security.instrumentation.grpc1400.client;

import com.google.protobuf.Any;
import com.google.protobuf.Descriptors;
import io.grpc.CallOptions;
import io.grpc.Channel;
import io.grpc.MethodDescriptor;
import io.grpc.stub.StreamObserver;

import java.util.Iterator;

import static io.grpc.MethodDescriptor.generateFullMethodName;

public class GrpcStubs {
    public static final class CustomStub extends io.grpc.stub.AbstractBlockingStub<CustomStub> {
        public static CustomStub newBlockingStub(
                Channel channel) {
            StubFactory<CustomStub> factory =
                    new StubFactory<CustomStub>() {
                        @Override
                        public CustomStub newStub(Channel channel, CallOptions callOptions) {
                            return new CustomStub(channel, callOptions);
                        }
                    };
            return CustomStub.newStub(factory, channel);
        }

        private CustomStub(
                Channel channel, CallOptions callOptions) {
            super(channel, callOptions);
        }

        @Override
        protected CustomStub build(Channel channel, CallOptions callOptions) {
            return new CustomStub(channel, callOptions);
        }

        public Any unaryCall(Any request, String serviceName, String methodName, Descriptors.Descriptor descriptor) {
            return io.grpc.stub.ClientCalls.blockingUnaryCall(
                    getChannel(), getSimpleMethod(serviceName, methodName, descriptor), getCallOptions(), request);
        }

        public Iterator<Any> serverStream(Any request, String serviceName, String methodName, Descriptors.Descriptor descriptor) {
            return io.grpc.stub.ClientCalls.blockingServerStreamingCall(
                    getChannel(), getServerStreamMethod(serviceName, methodName, descriptor), getCallOptions(), request);
        }

        public StreamObserver<Any> clientStream(StreamObserver<Any> responseObserver, String serviceName, String methodName, Descriptors.Descriptor descriptor) {
            return io.grpc.stub.ClientCalls.asyncClientStreamingCall(
                    getChannel().newCall(getClientStreamMethod(serviceName, methodName, descriptor), getCallOptions()), responseObserver);
        }

        public StreamObserver<Any> biDiStream(StreamObserver<Any> responseObserver, String serviceName, String methodName, Descriptors.Descriptor descriptor) {
            return io.grpc.stub.ClientCalls.asyncBidiStreamingCall(
                    getChannel().newCall(getBiDiMethod(serviceName, methodName, descriptor), getCallOptions()), responseObserver);
        }
    }

    private static final class CustomServiceMethodDescriptorSupplier
            implements io.grpc.protobuf.ProtoMethodDescriptorSupplier {
        private final String methodName;

        CustomServiceMethodDescriptorSupplier(String methodName) {
            this.methodName = methodName;
        }

        @Override
        public Descriptors.MethodDescriptor getMethodDescriptor() {
            return getServiceDescriptor().findMethodByName(methodName);
        }

        @Override
        public Descriptors.ServiceDescriptor getServiceDescriptor() {
            return null;
        }

        @Override
        public Descriptors.FileDescriptor getFileDescriptor() {
            return null;
        }
    }

    public static MethodDescriptor<Any, Any> getSimpleMethod(String serviceName, String methodName, Descriptors.Descriptor descriptor) {
        MethodDescriptor<Any, Any> getMethod;
        synchronized (GrpcStubs.class) {
            getMethod = MethodDescriptor.<Any, Any>newBuilder()
                            .setType(MethodDescriptor.MethodType.UNARY)
                            .setFullMethodName(generateFullMethodName(serviceName, methodName))
                            .setSampledToLocalTracing(true)
                            .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(Any.getDefaultInstance()))
                            .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(Any.getDefaultInstance()))
                            .setSchemaDescriptor(new CustomServiceMethodDescriptorSupplier(methodName))
                            .build();
        }
        return getMethod;
    }

    public static MethodDescriptor<Any, Any> getServerStreamMethod(String serviceName, String methodName, Descriptors.Descriptor descriptor) {
        MethodDescriptor<Any, Any> getMethod;
        synchronized (GrpcStubs.class) {
            getMethod = MethodDescriptor.<Any, Any>newBuilder()
                            .setType(MethodDescriptor.MethodType.SERVER_STREAMING)
                            .setFullMethodName(generateFullMethodName(serviceName, methodName))
                            .setSampledToLocalTracing(true)
                            .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(Any.getDefaultInstance()))
                            .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(Any.getDefaultInstance()))
                            .setSchemaDescriptor(new CustomServiceMethodDescriptorSupplier(methodName))
                            .build();
        }
        return getMethod;
    }

    public static MethodDescriptor<Any, Any> getClientStreamMethod(String serviceName, String methodName, Descriptors.Descriptor descriptor) {
        MethodDescriptor<Any, Any> getMethod;
        synchronized (GrpcStubs.class) {
            getMethod = MethodDescriptor.<Any, Any>newBuilder()
                            .setType(MethodDescriptor.MethodType.CLIENT_STREAMING)
                            .setFullMethodName(generateFullMethodName(serviceName, methodName))
                            .setSampledToLocalTracing(true)
                            .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(Any.getDefaultInstance()))
                            .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(Any.getDefaultInstance()))
                            .setSchemaDescriptor(new CustomServiceMethodDescriptorSupplier(methodName))
                            .build();
        }
        return getMethod;
    }

    public static MethodDescriptor<Any, Any> getBiDiMethod(String serviceName, String methodName, Descriptors.Descriptor descriptor) {
        io.grpc.MethodDescriptor<Any, Any> getMethod;
        synchronized (GrpcStubs.class) {
            getMethod = MethodDescriptor.<Any, Any>newBuilder()
                            .setType(io.grpc.MethodDescriptor.MethodType.BIDI_STREAMING)
                            .setFullMethodName(generateFullMethodName(serviceName, methodName))
                            .setSampledToLocalTracing(true)
                            .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(Any.getDefaultInstance()))
                            .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(Any.getDefaultInstance()))
                            .setSchemaDescriptor(new CustomServiceMethodDescriptorSupplier(methodName))
                            .build();
        }
        return getMethod;
    }

    public static CustomStub newBlockingStub(
            Channel channel) {
        io.grpc.stub.AbstractStub.StubFactory<CustomStub> factory =
                new io.grpc.stub.AbstractStub.StubFactory<CustomStub>() {
                    @Override
                    public CustomStub newStub(Channel channel, CallOptions callOptions) {
                        return new CustomStub(channel, callOptions);
                    }
                };
        return CustomStub.newStub(factory, channel);
    }

    public static CustomStub newStub(Channel channel) {
        io.grpc.stub.AbstractStub.StubFactory<CustomStub> factory =
                new io.grpc.stub.AbstractStub.StubFactory<CustomStub>() {
                    @Override
                    public CustomStub newStub(Channel channel, CallOptions callOptions) {
                        return new CustomStub(channel, callOptions);
                    }
                };
        return CustomStub.newStub(factory, channel);
    }
}
