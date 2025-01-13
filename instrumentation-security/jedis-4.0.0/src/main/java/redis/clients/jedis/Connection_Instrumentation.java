package redis.clients.jedis;

import com.newrelic.agent.security.instrumentation.jedis_4_0_0.JedisHelper;
import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import redis.clients.jedis.args.Rawable;

import java.util.ArrayList;
import java.util.List;

import static com.newrelic.agent.security.instrumentation.jedis_4_0_0.JedisHelper.NR_SEC_CUSTOM_ATTRIB_NAME;

@Weave(type = MatchType.BaseClass, originalName = "redis.clients.jedis.Connection")
public abstract class Connection_Instrumentation {
    public void sendCommand(final CommandArguments args) {
        boolean isLockAcquired = JedisHelper.acquireLockIfPossible(VulnerabilityCaseType.CACHING_DATA_STORE, args.hashCode());
        AbstractOperation operation = null;
        if(isLockAcquired && args.size()>1) { // args.size()>1 will ensure the event generation for the commands with data
                String command = "";
                List<Object> argList = new ArrayList<>();
                boolean pickCmd = false;
                for (Rawable arg : args) {
                    // first item in the list is always command type
                    if (!pickCmd){
                        command = new String(arg.getRaw());
                        pickCmd = true;
                        continue;
                    }
                    Object dataByBytes = NewRelicSecurity.getAgent()
                            .getSecurityMetaData()
                            .getCustomAttribute(GenericHelper.NR_SEC_CUSTOM_SPRING_REDIS_ATTR + arg.hashCode(), Object.class);
                    if(dataByBytes!=null){
                        argList.add(dataByBytes);
                    } else {
                        argList.add(new String(arg.getRaw()));
                    }
                }
                operation = JedisHelper.preprocessSecurityHook(command, argList, this.getClass().getName(), "sendCommand");
            }
        try {
            Weaver.callOriginal();
        } finally {
            if (isLockAcquired) {
                JedisHelper.releaseLock(args.hashCode());
            }
        }
        JedisHelper.registerExitOperation(isLockAcquired, operation);
    }
}
