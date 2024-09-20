package com.ibm.ws.tcpchannel.internal;

import com.ibm.websphere.channelfw.ChannelData;
import com.ibm.wsspi.channelfw.Channel;
import com.ibm.wsspi.channelfw.exception.ChannelException;
import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import java.util.Map;

@Weave
public class TCPChannelFactory {

    protected Channel createChannel(final ChannelData channelData) throws ChannelException {
        try {
            if (channelData.isInbound() && "defaultHttpEndpoint".equals(channelData.getExternalName())) {
                Map<Object, Object> propertyBag = channelData.getPropertyBag();
                if (propertyBag.containsKey("port")) {
                    try {
                        int port = Integer.parseInt((String) propertyBag.get("port"));
                        NewRelicSecurity.getAgent().setApplicationConnectionConfig(port, "http");
                    } catch (NumberFormatException e) {
                        NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.SERVER_CONFIG_ERROR, "WEBSPHERE_LIBERTY", e.getMessage()), e, this.getClass().getName());
                    }
                } else {
                    NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.SERVER_CONFIG_ERROR, "WEBSPHERE_LIBERTY", null), null, this.getClass().getName());
                }
            } else {
                NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.SERVER_CONFIG_ERROR, "WEBSPHERE_LIBERTY", null), null, this.getClass().getName());
            }
        } catch (Exception ignored) {
        }
        return Weaver.callOriginal();
    }
}
