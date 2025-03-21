/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package security.io.netty400.channel;

import com.newrelic.api.agent.security.instrumentation.helpers.ServletHelper;
import com.newrelic.api.agent.security.schema.StringUtils;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.http.HttpContent;
import io.netty.handler.codec.http.HttpRequest;
import security.io.netty400.utils.NettyUtils;

@Weave(type = MatchType.Interface, originalName = "io.netty.channel.ChannelInboundHandler")
public abstract class ChannelInboundHandler_Instrumentation {

    public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
        boolean isLockAcquired = false;
        if (msg instanceof HttpRequest || msg instanceof HttpContent){
            isLockAcquired = NettyUtils.acquireNettyLockIfPossible(NettyUtils.NR_SEC_NETTY_OPERATIONAL_LOCK);
        }
        if (isLockAcquired) {
            NettyUtils.processSecurityRequest(ctx, msg, getClass().getName());
            if (!StringUtils.startsWith(getClass().getName(), NettyUtils.IO_NETTY)) {
                ServletHelper.registerUserLevelCode(NettyUtils.IO_NETTY);
            }
        }
        try {
            Weaver.callOriginal();
        } finally {
            if (isLockAcquired) {
                NettyUtils.releaseNettyLock(NettyUtils.NR_SEC_NETTY_OPERATIONAL_LOCK);
            }
        }
    }
}
