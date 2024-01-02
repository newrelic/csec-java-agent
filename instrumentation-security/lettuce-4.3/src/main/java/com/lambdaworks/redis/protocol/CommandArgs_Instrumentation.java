package com.lambdaworks.redis.protocol;

import com.newrelic.api.agent.weaver.NewField;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;

import java.util.ArrayList;
import java.util.List;

@Weave(originalName = "com.lambdaworks.redis.protocol.CommandArgs")
public class CommandArgs_Instrumentation<K, V> {

    final List<CommandArgs.SingularArgument> singularArguments = Weaver.callOriginal();

//    @NewField
//    public List<CommandArgs.SingularArgument> singularArguments_instrumentation;

    public int count() {
        return Weaver.callOriginal();
    }

}
