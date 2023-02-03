package com.newrelic.agent.security.intcodeagent.websocket;

import com.newrelic.agent.security.AgentConfig;
import com.newrelic.agent.security.AgentInfo;
import com.newrelic.agent.security.intcodeagent.controlcommand.ControlCommandProcessor;
import com.newrelic.agent.security.intcodeagent.filelogging.FileLoggerThreadPool;
import com.newrelic.agent.security.intcodeagent.filelogging.LogLevel;
import com.newrelic.agent.security.intcodeagent.logging.IAgentConstants;
import org.apache.commons.lang3.StringUtils;
import org.java_websocket.WebSocket;
import org.java_websocket.WebSocketImpl;
import org.java_websocket.client.WebSocketClient;
import org.java_websocket.framing.CloseFrame;
import org.java_websocket.framing.Framedata;
import org.java_websocket.handshake.ServerHandshake;

import java.net.URI;
import java.net.URISyntaxException;
import java.time.Instant;
import java.time.ZoneId;
import java.util.concurrent.TimeUnit;

public class WSClient extends WebSocketClient {

    private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();
    public static final String SENDING_EVENT = "sending event: ";
    public static final String UNABLE_TO_SEND_EVENT = "Unable to send event : ";
    public static final String ERROR_IN_WSOCK_CONNECTION = "Error in WSock connection : ";
    public static final String CONNECTION_CLOSED_BY = "Connection closed by ";
    public static final String REMOTE_PEER = "remote peer.";
    public static final String LOCAL = "local.";
    public static final String CODE = " Code: ";
    public static final String REASON = " Reason: ";
    public static final String UNABLE_TO_PROCESS_INCOMING_MESSAGE = "Unable to process incoming message : ";
    public static final String DUE_TO_ERROR = " : due to error : ";
    public static final String RECONNECTING_TO_IC = "Reconnecting to validator";
    public static final String COLON_STRING = " : ";
    public static final String RECEIVED_PING_AT_S_SENDING_PONG = "received ping  at %s sending pong";

    private static WSClient instance;

    private WebSocketImpl connection = null;


    private WSClient() throws URISyntaxException {
        super(new URI(AgentConfig.getInstance().getConfig().getK2ServiceInfo().getValidatorServiceEndpointURL()));
        this.setTcpNoDelay(true);
        this.setConnectionLostTimeout(30);
        this.addHeader("NR-CSEC-CONNECTION-TYPE", "LANGUAGE_COLLECTOR");
        this.addHeader("NR-AGENT-RUN-TOKEN", AgentConfig.getInstance().getConfig().getCustomerInfo().getApiAccessorToken());
        this.addHeader("NR-CSEC-VERSION", AgentInfo.getInstance().getBuildInfo().getCollectorVersion());
        this.addHeader("NR-CSEC-COLLECTOR-TYPE", "JAVA");
        this.addHeader("NR-CSEC-BUILD-NUMBER", AgentInfo.getInstance().getBuildInfo().getBuildNumber());
        this.addHeader("NR-CSEC-MODE", AgentConfig.getInstance().getGroupName());
        this.addHeader("NR-CSEC-APP-UUID", AgentInfo.getInstance().getApplicationUUID());
        this.addHeader("NR-CSEC-JSON-VERSION", AgentInfo.getInstance().getBuildInfo().getJsonVersion());
        this.addHeader("NR-ACCOUNT-ID", AgentConfig.getInstance().getConfig().getCustomerInfo().getAccountId());
    }

    /**
     * Connects to K2 intcode over a websocket channel with the configuration provided in the constructor itself.
     *
     * @throws InterruptedException
     */
    public void openConnection() throws InterruptedException {
        logger.logInit(LogLevel.INFO, String.format(IAgentConstants.INIT_WS_CONNECTION, AgentConfig.getInstance().getConfig().getK2ServiceInfo().getValidatorServiceEndpointURL()),
                WSClient.class.getName());
        connectBlocking(10, TimeUnit.SECONDS);
        WebSocket conn = getConnection();
        if (conn instanceof WebSocketImpl) {
            this.connection = (WebSocketImpl) conn;
        }
    }

    @Override
    public void onOpen(ServerHandshake handshakedata) {
        logger.logInit(LogLevel.INFO, String.format(IAgentConstants.WS_CONNECTION_SUCCESSFUL, this.getRemoteSocketAddress()), WSClient.class.getName());
        logger.logInit(LogLevel.INFO, String.format(IAgentConstants.SENDING_APPLICATION_INFO_ON_WS_CONNECT, AgentInfo.getInstance().getApplicationInfo()), WSClient.class.getName());
        super.send(JsonConverter.toJSON(AgentInfo.getInstance().getApplicationInfo()));
        WSUtils.getInstance().setReconnecting(false);
        synchronized (WSUtils.getInstance()) {
            WSUtils.getInstance().notifyAll();
        }
        WSUtils.getInstance().setConnected(true);
        logger.logInit(LogLevel.INFO, String.format(IAgentConstants.APPLICATION_INFO_SENT_ON_WS_CONNECT, AgentInfo.getInstance().getApplicationInfo()), WSClient.class.getName());
    }

    @Override
    public void onMessage(String message) {
        // Receive communication from IC side.
        try {
            ControlCommandProcessor.processControlCommand(message, System.currentTimeMillis());
        } catch (Throwable e) {
            logger.log(LogLevel.FATAL, UNABLE_TO_PROCESS_INCOMING_MESSAGE + message + DUE_TO_ERROR, e,
                    WSClient.class.getName());
        }
    }

    @Override
    public void onClose(int code, String reason, boolean remote) {
        WSUtils.getInstance().setConnected(false);
        logger.log(LogLevel.WARN, CONNECTION_CLOSED_BY + (remote ? REMOTE_PEER : LOCAL) + CODE + code
                + REASON + reason, WSClient.class.getName());
        if (code == CloseFrame.NEVER_CONNECTED) {
            return;
        }

        if (code != CloseFrame.POLICY_VALIDATION && code != CloseFrame.NORMAL) {
            WSReconnectionST.getInstance().submitNewTaskSchedule();
        }
    }

    @Override
    public void onError(Exception ex) {
//        logger.log(LogLevel.SEVERE, "Error in WSock connection : " + ex.getMessage() + " : " + ex.getCause(),
//                WSClient.class.getName());
        logger.logInit(LogLevel.FATAL, String.format(IAgentConstants.WS_CONNECTION_UNSUCCESSFUL, AgentConfig.getInstance().getConfig().getK2ServiceInfo().getValidatorServiceEndpointURL()),
                ex,
                WSClient.class.getName());
    }

    @Override
    public void send(String text) {
        if (StringUtils.isBlank(text)) {
            return;
        }
        if (this.isOpen()) {
            logger.log(LogLevel.DEBUG, SENDING_EVENT + text, WSClient.class.getName());
            super.send(text);
        } else {
            logger.log(LogLevel.DEBUG, UNABLE_TO_SEND_EVENT + text, WSClient.class.getName());
        }
    }

    @Override
    public void onWebsocketPing(WebSocket conn, Framedata f) {
        logger.log(LogLevel.DEBUG, String.format(RECEIVED_PING_AT_S_SENDING_PONG, Instant.now().atZone(ZoneId.of("UTC")).toLocalTime()), WSClient.class.getName());
        if (connection != null) {
            connection.updateLastPong();
        }
        super.onWebsocketPing(conn, f);
    }

    /**
     * @return the instance
     * @throws URISyntaxException
     */
    public static WSClient getInstance() throws URISyntaxException, InterruptedException {
        if (instance == null) {
            instance = new WSClient();
        }
        return instance;
    }

    /**
     * @return the instance
     * @throws URISyntaxException
     * @throws InterruptedException
     */
    public static WSClient reconnectWSClient() throws URISyntaxException, InterruptedException {
        logger.log(LogLevel.WARN, RECONNECTING_TO_IC,
                WSClient.class.getName());
        if (instance != null) {
            instance.closeBlocking();
        }
        instance = new WSClient();
        instance.openConnection();
        return instance;
    }

    public static void shutDownWSClient() {
        logger.log(LogLevel.WARN, "Disconnecting WS client",
                WSClient.class.getName());
        if (instance != null) {
            try {
                instance.closeBlocking();
            } catch (InterruptedException e) {
            }
        }
        instance = null;
    }

}
