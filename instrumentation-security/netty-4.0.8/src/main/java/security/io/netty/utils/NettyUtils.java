package security.io.netty.utils;

import com.newrelic.api.agent.NewRelic;
import com.newrelic.api.agent.Transaction;
import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.schema.SecurityMetaData;
import io.netty.handler.codec.http.HttpRequest;
import io.netty.handler.codec.http.LastHttpContent;
import security.io.netty.channel.ChannelHandlerContext_Instrumentation;

import java.nio.charset.StandardCharsets;
import java.util.Map;

public class NettyUtils {

    public static void processSecurityHook(ChannelHandlerContext_Instrumentation ctx, Object msg) {
        System.out.println("inside processSecurityHook");
        Transaction tx = NewRelic.getAgent().getTransaction();
        Object secMetaObj = tx.getSecurityMetaData();
        if (msg instanceof HttpRequest) {
            if (!(secMetaObj instanceof SecurityMetaData) ||
                    NewRelicSecurity.getAgent().getSecurityMetaData() == null) {
                System.out.println("Return since sec meta not found");
                return;
            }
            com.newrelic.api.agent.security.schema.HttpRequest securityRequest =
                    NewRelicSecurity.getAgent().getSecurityMetaData().getRequest();

            if (!NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty()) {
                System.out.println("Return since req not empty");
                return;
            }
            System.out.println("Inside 1 channelRead");
            securityRequest.setMethod(((HttpRequest) msg).getMethod().name());
            securityRequest.setUrl(((HttpRequest) msg).getUri());
            securityRequest.setClientIP(ctx.channel().remoteAddress().toString());
            for (Map.Entry<String, String> entry : ((HttpRequest) msg).headers().entries()) {
                securityRequest.getHeaders().put(entry.getKey(), entry.getValue());
            }

        } else if (msg instanceof LastHttpContent) {
            if (!(secMetaObj instanceof SecurityMetaData) ||
                    NewRelicSecurity.getAgent().getSecurityMetaData() == null) {
                System.out.println("Return since sec meta not found");
                return;
            }
            com.newrelic.api.agent.security.schema.HttpRequest securityRequest =
                    NewRelicSecurity.getAgent().getSecurityMetaData().getRequest();
            securityRequest.getBody().append(((LastHttpContent) msg).content().toString(StandardCharsets.UTF_8));
        }
    }
}
