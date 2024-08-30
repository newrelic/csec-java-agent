package redis.clients.jedis;

import com.newrelic.agent.security.instrumentation.jedis_3_0_0.JedisHelper;
import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import redis.clients.jedis.Connection;
import redis.clients.jedis.Protocol;
import redis.clients.jedis.commands.ProtocolCommand;

import java.util.ArrayList;
import java.util.List;

import static com.newrelic.agent.security.instrumentation.jedis_3_0_0.JedisHelper.NR_SEC_CUSTOM_ATTRIB_NAME;

@Weave(type = MatchType.BaseClass, originalName = "redis.clients.jedis.Connection")
public abstract class Connection_Instrumentation {
    public void sendCommand(final ProtocolCommand cmd, final byte[]... args) {
        boolean isLockAcquired = JedisHelper.acquireLockIfPossible(VulnerabilityCaseType.CACHING_DATA_STORE, cmd.hashCode());
        AbstractOperation operation = null;
        if(isLockAcquired && args != null && args.length > 0) { // args.length>0 will ensure the event generation for the commands with data
            List<Object> argList = new ArrayList<>();
            for (byte[] arg : args) {
                Object dataByBytes = NewRelicSecurity.getAgent()
                        .getSecurityMetaData()
                        .getCustomAttribute(GenericHelper.NR_SEC_CUSTOM_SPRING_REDIS_ATTR + arg.hashCode(), Object.class);
                if (dataByBytes != null) {
                    argList.add(dataByBytes);
                } else {
                    argList.add(new String(arg));
                }
            }
            operation = JedisHelper.preprocessSecurityHook(new String(cmd.getRaw()), argList, this.getClass().getName(), "sendCommand");
        }
        try {
            Weaver.callOriginal();
        } finally {
            if (isLockAcquired) {
                JedisHelper.releaseLock(cmd.hashCode());
            }
        }
        JedisHelper.registerExitOperation(isLockAcquired, operation);
    }
}
