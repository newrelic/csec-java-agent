package com.newrelic.agent.security.intcodeagent.communication;

import com.newrelic.agent.security.AgentConfig;
import com.newrelic.agent.security.intcodeagent.apache.httpclient.SecurityClient;
import com.newrelic.agent.security.intcodeagent.filelogging.FileLoggerThreadPool;
import com.newrelic.agent.security.intcodeagent.websocket.WSClient;
import com.newrelic.agent.security.intcodeagent.websocket.WSReconnectionST;
import com.newrelic.api.agent.NewRelic;
import com.newrelic.api.agent.security.schema.StringUtils;
import com.newrelic.api.agent.security.utils.SecurityConnection;
import com.newrelic.api.agent.security.utils.logging.LogLevel;

import java.net.URISyntaxException;

public class ConnectionFactory {

    private SecurityConnection securityConnection;

    private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

    private ConnectionFactory() {
        /*
        Priority Order
        1. Env
        2. Config
        3. Mode
        * */

        String connection = NewRelic.getAgent().getConfig().getValue("security.connection");
        if(StringUtils.isBlank(connection)) {
            String mode = AgentConfig.getInstance().getAgentMode().getMode();
            if(StringUtils.equals("IAST_MONITORING", mode)){
                connection = "http";
            } else {
                connection = "ws";
            }
        }

        if(StringUtils.equals("http", connection)) {
            securityConnection = SecurityClient.getInstance();
        } else {
            try {
                WSReconnectionST.getInstance().submitNewTaskSchedule(0);
                securityConnection = WSClient.getInstance();
            } catch (URISyntaxException e) {
                logger.log(LogLevel.SEVERE, "Error while creating WSClient", e, ConnectionFactory.class.getName());
            }
        }
    }

    static class InstanceHolder {
        static final ConnectionFactory INSTANCE = new ConnectionFactory();
    }

    public static ConnectionFactory getInstance() {
        return InstanceHolder.INSTANCE;
    }

    public SecurityConnection getSecurityConnection() {
        return securityConnection;
    }

    public void setSecurityConnection(SecurityConnection securityConnection) {
        this.securityConnection = securityConnection;
    }


}
