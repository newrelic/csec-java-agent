package security.io.netty400.channel;

import com.newrelic.api.agent.security.instrumentation.helpers.ServletHelper;
import com.newrelic.api.agent.security.schema.StringUtils;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import io.netty.channel.ChannelHandlerContext;
import security.io.netty400.utils.NettyUtils;

@Weave(type = MatchType.BaseClass, originalName = "io.netty.channel.SimpleChannelInboundHandler")
public class SimpleChannelInboundHandler_Instrumentation<I> {

    protected void channelRead0(ChannelHandlerContext ctx, I msg) throws Exception {
        try {
            if (!StringUtils.startsWith(getClass().getName(), NettyUtils.IO_NETTY)) {
                ServletHelper.registerUserLevelCode(NettyUtils.IO_NETTY);
            }
        } catch (Exception e){
        }
        Weaver.callOriginal();
    }
}
