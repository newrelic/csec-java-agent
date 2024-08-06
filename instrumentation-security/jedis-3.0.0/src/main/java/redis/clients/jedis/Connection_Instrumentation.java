package redis.clients.jedis;

import com.newrelic.agent.security.instrumentation.jedis_3_0_0.JedisHelper;
import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.ExternalConnectionType;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.WeaveAllConstructors;
import com.newrelic.api.agent.weaver.Weaver;
import redis.clients.jedis.commands.ProtocolCommand;

import java.net.Socket;
import java.util.ArrayList;
import java.util.List;


@Weave(type = MatchType.BaseClass, originalName = "redis.clients.jedis.Connection")
public abstract class Connection_Instrumentation {

    public abstract Socket getSocket();
    public abstract int getPort();
    public abstract String getHost();

    @WeaveAllConstructors
    public Connection_Instrumentation() {
        try {
            NewRelicSecurity.getAgent().recordExternalConnection(getHost(), getPort(), null, getSocket().getInetAddress().getHostAddress(), ExternalConnectionType.DATABASE_CONNECTION.name(), "JEDIS-3.0.0");
        } catch (Exception e) {
            NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.ERROR_WHILE_DETECTING_CONNECTION_STATS, "JEDIS-3.0.0", e.getMessage()), this.getClass().getName());
        }
    }

    public void sendCommand(final ProtocolCommand cmd, final byte[]... args) {
        boolean isLockAcquired = JedisHelper.acquireLockIfPossible(cmd.hashCode());
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
