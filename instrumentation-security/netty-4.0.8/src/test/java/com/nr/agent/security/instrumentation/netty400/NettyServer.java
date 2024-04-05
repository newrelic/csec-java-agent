package com.nr.agent.security.instrumentation.netty400;

import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import io.netty.bootstrap.ServerBootstrap;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelPipeline;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.handler.codec.http.DefaultFullHttpResponse;
import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.codec.http.FullHttpResponse;
import io.netty.handler.codec.http.HttpHeaders;
import io.netty.handler.codec.http.HttpObjectAggregator;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.netty.handler.codec.http.HttpServerCodec;
import io.netty.handler.codec.http.HttpVersion;
import io.netty.handler.logging.LogLevel;
import io.netty.handler.logging.LoggingHandler;
import io.netty.util.CharsetUtil;
import org.junit.rules.ExternalResource;

import java.net.MalformedURLException;
import java.net.URL;

public class NettyServer extends ExternalResource {
    private Channel channel;
    private int PORT;

    @Override
    protected void before() throws Throwable {
        PORT = SecurityInstrumentationTestRunner.getIntrospector().getRandomPort();
        startServer();
    }

    @Override
    protected void after() {
        stopServer();
    }
    private void startServer() throws InterruptedException {
        ServerBootstrap b = new ServerBootstrap();
        b.group(new NioEventLoopGroup(),new NioEventLoopGroup())
            .channel(NioServerSocketChannel.class)
            .handler(new LoggingHandler(LogLevel.INFO))
            .childHandler(new ChannelInitializer<Channel>() {
                @Override
                protected void initChannel(Channel ch) throws Exception {
                ChannelPipeline pipeline = ch.pipeline();
                pipeline.addLast(new HttpServerCodec());
                pipeline.addLast(new HttpObjectAggregator(65536));
                pipeline.addLast(new SimpleChannelInboundHandler<FullHttpRequest>() {
                    @Override
                    protected void channelRead0(ChannelHandlerContext ctx, FullHttpRequest o) throws Exception {
                       o.content();
                    FullHttpResponse response = new DefaultFullHttpResponse(
                            HttpVersion.HTTP_1_0,
                            HttpResponseStatus.OK,
                            Unpooled.copiedBuffer("write data", CharsetUtil.UTF_8));
                    HttpHeaders.addHeader(response, HttpHeaders.Names.CONTENT_TYPE, "text/html");
                    ctx.writeAndFlush(response).addListener(ChannelFutureListener.CLOSE);
                    }
                });
                }
            });

        channel = b.bind(PORT).sync().channel();
        System.out.println("checking...");
    }

    private void stopServer(){
        if (channel.isActive() && channel.isOpen()){
            channel.close();
        }
    }
    public URL getEndPoint() throws MalformedURLException {
        return new URL("http://localhost:" + PORT + "/");
    }
}
