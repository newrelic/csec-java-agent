package io.lettuce.core;

import com.newrelic.agent.security.instrumentation.lettuce_6_0.LettuceUtils;
import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.schema.ExternalConnectionType;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import io.lettuce.core.resource.ClientResources;

@Weave(originalName = "io.lettuce.core.RedisClient")
public abstract class RedisClient_Instrumentation extends AbstractRedisClient {

    private final RedisURI redisURI = Weaver.callOriginal();

    protected RedisClient_Instrumentation(ClientResources clientResources, RedisURI redisURI) {
        super(clientResources);
        try {
            NewRelicSecurity.getAgent().recordExternalConnection(redisURI.getHost(), redisURI.getPort(), null, null,
                    ExternalConnectionType.DATABASE_CONNECTION.name(), LettuceUtils.LETTUCE_5_0);
        } catch (Exception e){
            NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.ERROR_WHILE_DETECTING_CONNECTION_STATS, LettuceUtils.LETTUCE_5_0, e.getMessage()), this.getClass().getName());
        }
    }
}
