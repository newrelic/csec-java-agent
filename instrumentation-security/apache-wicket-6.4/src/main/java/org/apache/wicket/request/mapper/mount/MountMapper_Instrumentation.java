package org.apache.wicket.request.mapper.mount;

import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.agent.security.instrumentation.apache.wicket6.WicketHelper;
import org.apache.wicket.request.IRequestMapper;

@Weave(type = MatchType.ExactClass, originalName = "org.apache.wicket.request.mapper.mount.MountMapper")
public class MountMapper_Instrumentation {
    public MountMapper_Instrumentation(String mountPath, IRequestMapper mapper) {
        try{
            WicketHelper.getMappings(mountPath, WicketHelper.getPackageMap().get(mapper.hashCode()), true);
            WicketHelper.getPackageMap().remove(mapper.hashCode());
        } catch (Exception ignored){
        }
    }
}
