/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package security.io.netty400.channel;

import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelPromise;
import io.netty.handler.codec.http.FullHttpResponse;
import security.io.netty400.utils.NettyUtils;

@Weave(type = MatchType.Interface, originalName = "io.netty.channel.ChannelOutboundHandler")
public abstract class ChannelOutboundHandler_Instrumentation {

    public void write(ChannelHandlerContext ctx, Object msg, ChannelPromise promise) throws Exception {
        boolean isLockAcquired = false;
        if (msg instanceof FullHttpResponse){
            isLockAcquired = NettyUtils.acquireNettyLockIfPossible(NettyUtils.NR_SEC_NETTY_OPERATIONAL_LOCK_OUTBOUND);
        }
        if (isLockAcquired) {
            NettyUtils.processSecurityResponse(ctx, msg);
            NettyUtils.sendRXSSEvent(ctx, msg, getClass().getName(), NettyUtils.WRITE_METHOD_NAME);
        }
        try {
            Weaver.callOriginal();
        } finally {
            if (isLockAcquired) {
                NettyUtils.releaseNettyLock(NettyUtils.NR_SEC_NETTY_OPERATIONAL_LOCK_OUTBOUND);
            }
        }
    }
}
