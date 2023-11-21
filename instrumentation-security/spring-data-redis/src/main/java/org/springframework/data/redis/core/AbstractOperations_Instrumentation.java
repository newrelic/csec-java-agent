package org.springframework.data.redis.core;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;

@Weave(type = MatchType.BaseClass, originalName = "org.springframework.data.redis.core.AbstractOperations")
abstract class AbstractOperations_Instrumentation {

    <HK> byte[] rawHashKey(HK hashKey) {
        byte[] returnValue = null;
        returnValue = Weaver.callOriginal();

        createRedisArgumentEntry(returnValue.hashCode(), hashKey);

        return returnValue;
    }

    <HV> byte[] rawHashValue(HV value) {
        byte[] returnValue = null;
        returnValue = Weaver.callOriginal();

        createRedisArgumentEntry(returnValue.hashCode(), value);

        return returnValue;
    }

    byte[] rawKey(Object key) {
        System.out.println("raw key : "+key);
        byte[] returnValue = null;
        returnValue = Weaver.callOriginal();

        createRedisArgumentEntry(returnValue.hashCode(), key);

        return returnValue;
    }

    byte[] rawString(String key) {
        byte[] returnValue = null;
        returnValue = Weaver.callOriginal();

        createRedisArgumentEntry(returnValue.hashCode(), key);

        return returnValue;
    }

    byte[] rawValue(Object value) {
        System.out.println("raw value : "+value);
        byte[] returnValue = null;
        returnValue = Weaver.callOriginal();

        createRedisArgumentEntry(returnValue.hashCode(), value);

        return returnValue;
    }

    private void createRedisArgumentEntry(int hashCode, Object entry) {
        System.out.println("Arguments hash call for obj "+ hashCode + ":" + entry);
        if (!NewRelicSecurity.isHookProcessingActive() ||
                NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty()){
            return;
        }
        NewRelicSecurity.getAgent().getSecurityMetaData().addCustomAttribute(GenericHelper.NR_SEC_CUSTOM_SPRING_REDIS_ATTR + hashCode, entry);
    }
}
