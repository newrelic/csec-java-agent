package com.lambdaworks.redis;

import com.lambdaworks.redis.codec.RedisCodec;
import com.lambdaworks.redis.protocol.CommandHandler;
import com.newrelic.agent.security.instrumentation.lettuce_4_3.LettuceUtils;
import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.schema.ExternalConnectionType;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;

import java.util.concurrent.TimeUnit;

@SuppressWarnings("deprecation")
@Weave(originalName = "com.lambdaworks.redis.RedisClient")
public abstract class RedisClient_Instrumentation extends AbstractRedisClient {

    private final RedisURI redisURI = Weaver.callOriginal();

    protected <K, V> StatefulRedisConnectionImpl<K, V> newStatefulRedisConnection(CommandHandler<K, V> commandHandler, RedisCodec<K, V> codec, long timeout, TimeUnit unit){
        StatefulRedisConnectionImpl<K, V> redisConnection = Weaver.callOriginal();
        try {
            NewRelicSecurity.getAgent().recordExternalConnection(redisURI.getHost(), redisURI.getPort(), null, redisURI.getResolvedAddress().toString(),
                    ExternalConnectionType.DATABASE_CONNECTION.name(), LettuceUtils.LETTUCE_4_3);
        } catch (Exception e){
            NewRelicSecurity.getAgent().log(
                    LogLevel.WARNING, String.format(GenericHelper.ERROR_WHILE_DETECTING_CONNECTION_STATS, LettuceUtils.LETTUCE_4_3, e.getMessage()), this.getClass().getName());
        }
        return redisConnection;
    }
}
