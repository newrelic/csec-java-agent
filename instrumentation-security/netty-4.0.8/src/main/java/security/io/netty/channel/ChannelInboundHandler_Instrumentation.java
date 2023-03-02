/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package security.io.netty.channel;

import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import security.io.netty.utils.NettyUtils;

@Weave(type = MatchType.Interface, originalName = "io.netty.channel.ChannelInboundHandler")
public abstract class ChannelInboundHandler_Instrumentation {

    public void channelRead(ChannelHandlerContext_Instrumentation ctx, Object msg) throws Exception {
        Weaver.callOriginal();
        NettyUtils.processSecurityHook(ctx, msg);
    }
}
