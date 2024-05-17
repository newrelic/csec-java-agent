package com.nr.agent.security.instrumentation.netty400;

import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.api.agent.Trace;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.HttpRequest;
import com.newrelic.api.agent.security.schema.HttpResponse;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.security.schema.operation.RXSSOperation;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelInboundHandlerAdapter;

import io.netty.channel.ChannelOutboundHandlerAdapter;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.handler.codec.http.DefaultFullHttpRequest;
import io.netty.handler.codec.http.DefaultFullHttpResponse;
import io.netty.handler.codec.http.DefaultHttpContent;
import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.codec.http.FullHttpResponse;
import io.netty.handler.codec.http.HttpMethod;
import io.netty.handler.codec.http.HttpResponseEncoder;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.netty.handler.codec.http.HttpVersion;
import org.junit.Assert;
import org.junit.ClassRule;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;
import security.io.netty400.utils.NettyUtils;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.util.List;

@RunWith(SecurityInstrumentationTestRunner.class)
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@InstrumentationTestConfig(includePrefixes = {"security.io.netty400"})
public class NettyTest {

    @ClassRule
    public static NettyServer server = new NettyServer();

    private final String header = "text/html";
    @Test
    public void testChannelRXSS() throws IOException {
        connect();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertFalse("No operations detected", operations.isEmpty());

        RXSSOperation operation = (RXSSOperation) operations.get(0);
        Assert.assertEquals("Invalid executed method name", NettyUtils.WRITE_METHOD_NAME, operation.getMethodName());
        Assert.assertEquals("Invalid event category", VulnerabilityCaseType.REFLECTED_XSS, operation.getCaseType());

        HttpResponse response = introspector.getSecurityMetaData().getResponse();
        Assert.assertEquals("Invalid content-type body", header, response.getResponseContentType());
        Assert.assertEquals("Invalid content-type body", header, response.getHeaders().get("content-type"));
        Assert.assertEquals("Invalid response body", "write data", response.getResponseBody().toString());
    }
    @Test
    public void testChannelRead() {
        channelRead();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertTrue("Operations detected", operations.isEmpty());

        HttpRequest request = introspector.getSecurityMetaData().getRequest();
        Assert.assertEquals("Invalid protocol", "http", request.getProtocol());
        Assert.assertNotNull("No URL", request.getUrl());
        Assert.assertEquals("Invalid content-type", header, request.getContentType());
        Assert.assertEquals("Invalid headers", header, request.getHeaders().get("content-type"));
        Assert.assertEquals("Invalid request body", "read data", request.getBody().toString());
    }

    @Test
    public void testWrite() {
        write();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertFalse("No operations detected", operations.isEmpty());

        RXSSOperation operation = (RXSSOperation) operations.get(0);
        Assert.assertEquals("Invalid executed method name", NettyUtils.WRITE_METHOD_NAME, operation.getMethodName());
        Assert.assertEquals("Invalid event category", VulnerabilityCaseType.REFLECTED_XSS, operation.getCaseType());

        HttpResponse response = introspector.getSecurityMetaData().getResponse();
        Assert.assertEquals("Invalid content-type body", header, response.getResponseContentType());
        Assert.assertEquals("Invalid content-type body", header, response.getHeaders().get("content-type"));
        Assert.assertEquals("Invalid response body", "write data", response.getResponseBody().toString());
    }

    @Test
    public void testWriteAndFlush() {
        writeAndFlush();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertFalse("No operations detected", operations.isEmpty());

        RXSSOperation operation = (RXSSOperation) operations.get(0);
        Assert.assertEquals("Invalid executed method name", NettyUtils.WRITE_METHOD_NAME, operation.getMethodName());
        Assert.assertEquals("Invalid event category", VulnerabilityCaseType.REFLECTED_XSS, operation.getCaseType());

        HttpResponse response = introspector.getSecurityMetaData().getResponse();
        Assert.assertEquals("Invalid content-type body", header, response.getResponseContentType());
        Assert.assertEquals("Invalid content-type body", header, response.getHeaders().get("content-type"));
        Assert.assertEquals("Invalid response body", "write flush data", response.getResponseBody().toString());
    }

    @Test
    public void testWriteAndFlushPromise() {
        writeAndFlushPromise();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertFalse("No operations detected", operations.isEmpty());

        RXSSOperation operation = (RXSSOperation) operations.get(0);
        Assert.assertEquals("Invalid executed method name", NettyUtils.WRITE_METHOD_NAME, operation.getMethodName());
        Assert.assertEquals("Invalid event category", VulnerabilityCaseType.REFLECTED_XSS, operation.getCaseType());

        HttpResponse response = introspector.getSecurityMetaData().getResponse();
        Assert.assertEquals("Invalid content-type body", header, response.getResponseContentType());
        Assert.assertEquals("Invalid content-type body", header, response.getHeaders().get("content-type"));
        Assert.assertEquals("Invalid response body", "write flush promise data", response.getResponseBody().toString());
    }

    @Test
    public void testEncode() {
        encode();

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        List<AbstractOperation> operations = introspector.getOperations();
        Assert.assertFalse("No operations detected", operations.isEmpty());

        RXSSOperation operation = (RXSSOperation) operations.get(0);
        Assert.assertEquals("Invalid executed method name", NettyUtils.WRITE_METHOD_NAME, operation.getMethodName());
        Assert.assertEquals("Invalid event category", VulnerabilityCaseType.REFLECTED_XSS, operation.getCaseType());

        HttpResponse response = introspector.getSecurityMetaData().getResponse();
        Assert.assertEquals("Invalid content-type body", header, response.getResponseContentType());
        Assert.assertEquals("Invalid content-type body", header, response.getHeaders().get("content-type"));
        Assert.assertEquals("Invalid response body", "encode data", response.getResponseBody().toString());
    }

    @Trace(dispatcher = true)
    private void channelRead() {
        EmbeddedChannel channel = new EmbeddedChannel(new ChannelInboundHandlerAdapter());
        FullHttpRequest httpRequest = new DefaultFullHttpRequest(HttpVersion.HTTP_1_0, HttpMethod.POST, "/test");
        httpRequest.headers().add("content-type", header);
        DefaultHttpContent httpContent = new DefaultHttpContent(Unpooled.wrappedBuffer("read data".getBytes()));
//        httpRequest.content().writeBytes("read data".getBytes());
        channel.writeInbound(httpRequest, httpContent);
        channel.read();
    }

    @Trace(dispatcher = true)
    private void write() {
        EmbeddedChannel channel = new EmbeddedChannel(new ChannelOutboundHandlerAdapter());
        FullHttpResponse response = new DefaultFullHttpResponse(HttpVersion.HTTP_1_0, HttpResponseStatus.ACCEPTED);
        response.headers().add("content-type", header);
        response.content().writeBytes("write data".getBytes());

        channel.write(response);
        channel.flush();
    }

    @Trace(dispatcher = true)
    private void writeAndFlush() {
        EmbeddedChannel channel = new EmbeddedChannel(new ChannelOutboundHandlerAdapter());
        FullHttpResponse response = new DefaultFullHttpResponse(HttpVersion.HTTP_1_0, HttpResponseStatus.ACCEPTED);
        response.headers().add("content-type", header);
        response.content().writeBytes("write flush data".getBytes());

        channel.writeAndFlush(response);
    }

    @Trace(dispatcher = true)
    private void writeAndFlushPromise() {
        EmbeddedChannel channel = new EmbeddedChannel(new ChannelOutboundHandlerAdapter());
        FullHttpResponse response = new DefaultFullHttpResponse(HttpVersion.HTTP_1_0, HttpResponseStatus.ACCEPTED);
        response.headers().add("content-type", header);
        response.content().writeBytes("write flush promise data".getBytes());

        channel.writeAndFlush(response, channel.newPromise());
    }

    @Trace(dispatcher = true)
    private void encode() {
        EmbeddedChannel channel = new EmbeddedChannel(new ChannelOutboundHandlerAdapter());
        channel.pipeline().addLast(new HttpResponseEncoder());
        FullHttpResponse response = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.ACCEPTED);
        response.headers().add("content-type", header);
        response.content().writeBytes("encode data".getBytes());

        channel.write(response);
        channel.flush();
    }
    @Trace(dispatcher = true)
    private void connect() throws IOException {
        HttpURLConnection connection = (HttpURLConnection) server.getEndPoint().openConnection();
        connection.setDoOutput(true);
        connection.setRequestMethod("POST");
        connection.setRequestProperty("content-type", header);
        connection.getOutputStream().write("name=ishi".getBytes());

        connection.connect();
        System.out.println(connection.getResponseCode());
    }
}