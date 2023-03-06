/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package security.io.netty.handler.codec.http;

import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import io.netty.channel.ChannelHandlerContext;
import security.io.netty.utils.NettyUtils;

import java.util.List;

@Weave(type = MatchType.BaseClass, originalName = "io.netty.handler.codec.http.HttpObjectEncoder")
public class HttpObjectEncoder_Instrumentation {

    // heading downstream
    protected void encode(ChannelHandlerContext ctx, Object msg, List<Object> out) {
        // TODO : Process response here
        NettyUtils.processSecurityResponse(ctx, msg);
        Weaver.callOriginal();
    }

}
