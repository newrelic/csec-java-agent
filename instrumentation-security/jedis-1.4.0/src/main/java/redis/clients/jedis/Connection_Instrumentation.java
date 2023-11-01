package redis.clients.jedis;

import com.newrelic.agent.security.instrumentation.jedis_1_4_0.JedisHelper;
import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;

import java.util.ArrayList;
import java.util.List;

@Weave(type = MatchType.BaseClass, originalName = "redis.clients.jedis.Connection")
public abstract class Connection_Instrumentation {
    protected Connection sendCommand(final Protocol.Command cmd, final byte[]... args) {
        boolean isLockAcquired = JedisHelper.acquireLockIfPossible(cmd.hashCode());
        AbstractOperation operation = null;
            if(isLockAcquired && cmd!=null && args!=null) {
                List<Object> argList = new ArrayList<>();
                for (int i=0; i < args.length; i++) {
                    Object dataByBytes = NewRelicSecurity.getAgent()
                            .getSecurityMetaData()
                            .getCustomAttribute(GenericHelper.NR_SEC_CUSTOM_SPRING_REDIS_ATTR + args[i].hashCode(), Object.class);

                    if(dataByBytes!=null){
                        argList.add(dataByBytes);
                    } else {
                        argList.add(new String(args[i]));
                    }
                }
                operation = JedisHelper.preprocessSecurityHook(cmd.name(), argList, this.getClass().getName(), "sendCommand");
            }
        Connection returnValue = null;
        try {
            returnValue = Weaver.callOriginal();
        } finally {
            if (isLockAcquired) {
                JedisHelper.releaseLock(cmd.hashCode());
            }
        }
        JedisHelper.registerExitOperation(isLockAcquired, operation);
        return returnValue;
    }
}
