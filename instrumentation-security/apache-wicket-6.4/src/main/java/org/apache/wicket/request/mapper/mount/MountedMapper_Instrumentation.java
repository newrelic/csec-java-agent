package org.apache.wicket.request.mapper.mount;

import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.WeaveAllConstructors;
import com.newrelic.api.agent.weaver.Weaver;
import com.nr.instrumentation.security.apache.wicket6.WicketHelper;
import org.apache.wicket.request.component.IRequestablePage;
import org.apache.wicket.util.IProvider;

@Weave(type = MatchType.ExactClass, originalName = "org.apache.wicket.core.request.mapper.MountedMapper")
public class MountedMapper_Instrumentation {
    private final String[] mountSegments = Weaver.callOriginal();
    private final IProvider<Class<? extends IRequestablePage>> pageClassProvider = Weaver.callOriginal();
    @WeaveAllConstructors
    public MountedMapper_Instrumentation(){
        WicketHelper.getMappings(mountSegments, pageClassProvider.get().getName(), false);
    }
}
