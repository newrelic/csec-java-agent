package redis.clients.jedis;

import com.newrelic.agent.security.instrumentation.jedis_4_0_0.JedisHelper;
import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.ExternalConnectionType;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import redis.clients.jedis.args.Rawable;
import redis.clients.jedis.exceptions.JedisConnectionException;

import java.util.ArrayList;
import java.util.List;


@Weave(type = MatchType.BaseClass, originalName = "redis.clients.jedis.Connection")
public abstract class Connection_Instrumentation {

    final HostAndPort getHostAndPort() {
       return Weaver.callOriginal();
    }

    public void connect() throws JedisConnectionException {
        Weaver.callOriginal();
        try {
            HostAndPort hostAndPort = getHostAndPort();
            NewRelicSecurity.getAgent().recordExternalConnection(hostAndPort.getHost(), hostAndPort.getPort(), null, null, ExternalConnectionType.DATABASE_CONNECTION.name(), "JEDIS-4.0.0");
        } catch (Exception e) {
            NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.ERROR_WHILE_DETECTING_CONNECTION_STATS, "JEDIS-4.0.0", e.getMessage()), this.getClass().getName());
        }
    }

    public void sendCommand(final CommandArguments args) {
        boolean isLockAcquired = JedisHelper.acquireLockIfPossible(args.hashCode());
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
