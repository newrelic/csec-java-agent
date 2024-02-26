/*
 *
 *  * Copyright 2021 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package com.nr.agent.security.instrumentation.grpc1400.app;

import com.google.common.util.concurrent.ListenableFuture;
import com.newrelic.api.agent.NewRelic;
import com.newrelic.api.agent.Segment;
import com.newrelic.api.agent.Trace;
import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;
import io.grpc.examples.helloworld.GreeterGrpc;
import io.grpc.examples.helloworld.HelloReply;
import io.grpc.examples.helloworld.HelloRequest;
import io.grpc.examples.manualflowcontrol.StreamingGreeterGrpc;
import io.grpc.stub.StreamObserver;

import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

public class TestClient {
    private final ManagedChannel channel;
    private final GreeterGrpc.GreeterBlockingStub greeterStub;
    private final GreeterGrpc.GreeterFutureStub greeterFutureStub;
    private final GreeterGrpc.GreeterStub asyncGreeterStub;
    private final StreamingGreeterGrpc.StreamingGreeterStub streamingGreeterStub;

    public TestClient(String host, int port) {
        this(ManagedChannelBuilder.forAddress(host, port)
                .usePlaintext()
                .build());
    }

    TestClient(ManagedChannel channel) {
        this.channel = channel;
        greeterStub = GreeterGrpc.newBlockingStub(channel);
        greeterFutureStub = GreeterGrpc.newFutureStub(channel);
        asyncGreeterStub = GreeterGrpc.newStub(channel);
        streamingGreeterStub = StreamingGreeterGrpc.newStub(channel);
    }

    public void shutdown() throws InterruptedException {
        channel.shutdown().awaitTermination(5, TimeUnit.SECONDS);
    }

    @Trace(dispatcher = true)
    public void helloBlocking(String name) {
        HelloRequest request = HelloRequest.newBuilder().setName(name).build();
        greeterStub.sayHello(request);
    }

    @Trace(dispatcher = true)
    public void helloFuture(String name) throws InterruptedException, ExecutionException, TimeoutException {
        HelloRequest request = HelloRequest.newBuilder().setName(name).build();
        ListenableFuture<HelloReply> helloReplyListenableFuture = greeterFutureStub.sayHello(request);
        helloReplyListenableFuture.get(10, TimeUnit.SECONDS);
    }

    @Trace(dispatcher = true)
    public void helloAsync(String name) {
        final Segment segment = NewRelic.getAgent().getTransaction().startSegment("helloAsync");

        HelloRequest request = HelloRequest.newBuilder().setName(name).build();
        asyncGreeterStub.sayHello(request, new StreamObserver<HelloReply>() {
            @Override
            public void onNext(HelloReply value) {
                System.out.println("Next: " + value);
            }

            @Override
            public void onError(Throwable t) {
            }

            @Override
            public void onCompleted() {
                segment.end();
            }
        });
    }

    @Trace(dispatcher = true)
    public void helloStreaming(String name) {
        final Segment segment = NewRelic.getAgent().getTransaction().startSegment("helloStreaming");

        StreamObserver<io.grpc.examples.manualflowcontrol.HelloRequest> stream = streamingGreeterStub.sayHelloStreaming(
                new StreamObserver<io.grpc.examples.manualflowcontrol.HelloReply>() {
                    @Override
                    public void onNext(io.grpc.examples.manualflowcontrol.HelloReply value) {
                        System.out.print("Next: " + value);
                    }

                    @Override
                    public void onError(Throwable t) {

                    }

                    @Override
                    public void onCompleted() {
                        segment.end();
                    }
                });


        long[] inputs = new long[] { 1, 2, 3, 4 };
        try {
            for (long input : inputs) {
                stream.onNext(io.grpc.examples.manualflowcontrol.HelloRequest.newBuilder()
                        .setName(name+input)
                        .build());
            }
        } catch (RuntimeException e) {
            e.printStackTrace();
            stream.onError(e);
        }
        stream.onCompleted();
    }

    @Trace(dispatcher = true)
    public void throwException(String name) {
        HelloRequest request = HelloRequest.newBuilder().setName(name).build();
        greeterStub.throwException(request);
    }

    @Trace(dispatcher = true)
    public void throwCaughtException(String name) {
        HelloRequest request = HelloRequest.newBuilder().setName(name).build();
        try {
            greeterStub.throwCaughtException(request);
        } catch (Exception e) {
        }
    }
}
