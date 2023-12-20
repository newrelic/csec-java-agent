package org.apache.wicket.core.request.mapper;

import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.nr.instrumentation.security.apache.wicket7.WicketHelper;
import org.apache.wicket.request.mapper.parameter.IPageParametersEncoder;
import org.apache.wicket.util.lang.PackageName;

@Weave(type = MatchType.ExactClass, originalName = "org.apache.wicket.core.request.mapper.PackageMapper")
public class PackageMapper_Instrumentation {

    public PackageMapper_Instrumentation(String mountPath, final PackageName packageName,
            final IPageParametersEncoder pageParametersEncoder){
        WicketHelper.getMappings(mountPath, packageName.getName(), true);
    }
}
