package org.apache.wicket.core.request.mapper;

import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.nr.instrumentation.security.apache.wicket8.WicketHelper;
import org.apache.wicket.request.component.IRequestablePage;
import org.apache.wicket.request.mapper.parameter.IPageParametersEncoder;

import java.util.function.Supplier;

@Weave(type = MatchType.BaseClass, originalName = "org.apache.wicket.core.request.mapper.MountedMapper")
public class MountedMapper_Instrumentation {
    public MountedMapper_Instrumentation(String mountPath,
            Supplier<Class<? extends IRequestablePage>> pageClassProvider,
            IPageParametersEncoder pageParametersEncoder
    ) {
        try{
            WicketHelper.getMappings(mountPath, pageClassProvider.get().getName(), false);
        } catch (Exception ignored) {
        }
    }
}
