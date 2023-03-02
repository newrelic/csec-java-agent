/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package security.io.netty.channel;

import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import io.netty.channel.Channel;

@Weave(type = MatchType.Interface, originalName = "io.netty.channel.ChannelHandlerContext")
public abstract class ChannelHandlerContext_Instrumentation {

    public abstract ChannelPipeline_Instrumentation pipeline();

    public abstract Channel channel();

}
