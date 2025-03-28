package org.mule.module.http.internal.listener.grizzly;

import com.newrelic.agent.security.instrumentation.mule37.MuleHelper;
import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import org.glassfish.grizzly.filterchain.FilterChainContext;
import org.glassfish.grizzly.filterchain.NextAction;

import java.io.IOException;
import java.net.InetSocketAddress;

@Weave(type = MatchType.ExactClass, originalName = "org.mule.module.http.internal.listener.grizzly.GrizzlyRequestDispatcherFilter")
public class GrizzlyRequestDispatcherFilter_Instrumentation {
    public NextAction handleRead(final FilterChainContext ctx) throws IOException {
        try {
            NewRelicSecurity.getAgent().getSecurityMetaData()
                    .addCustomAttribute(
                            MuleHelper.MULE_SERVER_PORT_ATTRIB_NAME,
                            ((InetSocketAddress)ctx.getConnection().getLocalAddress()).getPort()
                    );
        } catch (Exception ignored){}
        return Weaver.callOriginal();
    }
}
