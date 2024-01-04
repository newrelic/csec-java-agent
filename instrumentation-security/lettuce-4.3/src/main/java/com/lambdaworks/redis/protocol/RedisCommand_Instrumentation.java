package com.lambdaworks.redis.protocol;

import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;

@Weave(type = MatchType.Interface, originalName = "com.lambdaworks.redis.protocol.RedisCommand")
public abstract class RedisCommand_Instrumentation<K, V, T> {

    public abstract ProtocolKeyword getType();
    public CommandArgs_Instrumentation<K, V> getArgs() {
        return Weaver.callOriginal();
    }

}
