package com.lambdaworks.redis.protocol;

import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;

@Weave(type = MatchType.ExactClass, originalName = "com.lambdaworks.redis.protocol.CommandArgs$BytesArgument")
abstract class BytesArgument_Instrumentation  {
    private final byte[] val = Weaver.callOriginal();
}
