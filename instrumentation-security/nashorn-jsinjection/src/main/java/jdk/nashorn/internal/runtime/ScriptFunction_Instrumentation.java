package jdk.nashorn.internal.runtime;

import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.NewField;
import com.newrelic.api.agent.weaver.Weave;
import jdk.nashorn.internal.objects.Global;

@Weave(type = MatchType.ExactClass, originalName = "jdk.nashorn.internal.runtime.ScriptFunction")
public class ScriptFunction_Instrumentation {

    @NewField
    public ScriptFunctionData publicData;

    private ScriptFunction_Instrumentation(ScriptFunctionData data, PropertyMap map, ScriptObject scope, Global global) {
        this.publicData = data;
    }

}
