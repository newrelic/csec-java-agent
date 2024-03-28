package org.apache.wicket.request.mapper.mount;

import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.agent.security.instrumentation.apache.wicket6.WicketHelper;
import org.apache.wicket.request.mapper.parameter.IPageParametersEncoder;
import org.apache.wicket.util.lang.PackageName;

@Weave(type = MatchType.ExactClass, originalName = "org.apache.wicket.core.request.mapper.PackageMapper")
public abstract class PackageMapper_Instrumentation {
    public PackageMapper_Instrumentation (PackageName packageName, IPageParametersEncoder pageParametersEncoder) {
        WicketHelper.getPackageMap().put(hashCode(), packageName.getName());
    }
}
