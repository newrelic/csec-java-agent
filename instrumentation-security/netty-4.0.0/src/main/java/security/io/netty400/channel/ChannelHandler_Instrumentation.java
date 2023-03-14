/*
 *
 *  * Copyright 2022 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */
package security.io.netty400.channel;

import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import io.netty.channel.ChannelHandlerContext;

@Weave(type = MatchType.Interface, originalName = "io.netty.channel.ChannelHandler")
public class ChannelHandler_Instrumentation {

    /*
     * This is to solve a bug where the transaction is lost when spring webclient times out and throws an error
     * using the io.netty.handler.timeout.ReadTimeoutHandler class from netty.
     *
     * Any extra handlers used by netty will now link a transaction if available.
     *
     * -----------------------------------
     * WARNING
     * -----------------------------------
     *
     * Netty has marked this method as deprecated since 4.1
     *
     * If instrumentation verification fails for because of this class,
     * then in the new instrumentation module try instrumenting the class:
     *
     * io.netty.channel.AbstractChannelHandlerContext
     *
     * and its method:
     *
     * static void invokeExceptionCaught(final AbstractChannelHandlerContext next, final Throwable cause)
     *
     * */
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
        // TODO : Negative RXSS case. Read response.
        Weaver.callOriginal();
    }

}
