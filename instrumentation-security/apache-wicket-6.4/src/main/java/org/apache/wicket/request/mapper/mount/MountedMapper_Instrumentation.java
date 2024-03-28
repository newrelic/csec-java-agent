package org.apache.wicket.request.mapper.mount;

import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.agent.security.instrumentation.apache.wicket6.WicketHelper;
import org.apache.wicket.request.component.IRequestablePage;
import org.apache.wicket.request.mapper.parameter.IPageParametersEncoder;
import org.apache.wicket.util.IProvider;

@Weave(type = MatchType.ExactClass, originalName = "org.apache.wicket.core.request.mapper.MountedMapper")
public class MountedMapper_Instrumentation {

    public MountedMapper_Instrumentation(
            String mountPath,
            IProvider<Class<? extends IRequestablePage>> pageClassProvider,
            IPageParametersEncoder pageParametersEncoder
    ){
        WicketHelper.getMappings(mountPath, pageClassProvider.get().getName(), false);
    }
}
