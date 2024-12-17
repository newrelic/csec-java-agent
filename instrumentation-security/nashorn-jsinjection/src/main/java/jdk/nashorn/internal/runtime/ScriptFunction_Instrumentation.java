package jdk.nashorn.internal.runtime;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.agent.security.instrumentation.nashorn.JSEngineUtils;
import jdk.nashorn.internal.objects.Global;

@Weave(type = MatchType.ExactClass, originalName = "jdk.nashorn.internal.runtime.ScriptFunction")
public class ScriptFunction_Instrumentation {

    private ScriptFunction_Instrumentation(ScriptFunctionData data, PropertyMap map, ScriptObject scope, Global global) {
        if(data instanceof RecompilableScriptFunctionData && NewRelicSecurity.getAgent().getSecurityMetaData() != null) {
            Source source = ((RecompilableScriptFunctionData) data).getSource();
            NewRelicSecurity.getAgent().getSecurityMetaData().addCustomAttribute(JSEngineUtils.NASHORN_CONTENT + this.hashCode(), String.valueOf(source.getContent()));
        }
    }
}
