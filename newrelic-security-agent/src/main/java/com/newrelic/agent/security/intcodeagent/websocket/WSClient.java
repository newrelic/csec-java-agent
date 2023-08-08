package com.newrelic.agent.security.intcodeagent.websocket;

import com.newrelic.agent.security.AgentConfig;
import com.newrelic.agent.security.AgentInfo;
import com.newrelic.agent.security.instrumentator.dispatcher.DispatcherPool;
import com.newrelic.agent.security.instrumentator.httpclient.RestRequestThreadPool;
import com.newrelic.agent.security.instrumentator.utils.INRSettingsKey;
import com.newrelic.agent.security.intcodeagent.controlcommand.ControlCommandProcessor;
import com.newrelic.agent.security.intcodeagent.filelogging.FileLoggerThreadPool;
import com.newrelic.agent.security.intcodeagent.filelogging.LogLevel;
import com.newrelic.agent.security.intcodeagent.logging.IAgentConstants;
import com.newrelic.agent.security.intcodeagent.utils.CommonUtils;
import com.newrelic.agent.security.util.IUtilConstants;
import com.newrelic.api.agent.NewRelic;
import org.apache.commons.lang3.StringUtils;
import org.java_websocket.WebSocket;
import org.java_websocket.WebSocketImpl;
import org.java_websocket.client.WebSocketClient;
import org.java_websocket.drafts.Draft_6455;
import org.java_websocket.framing.CloseFrame;
import org.java_websocket.framing.Framedata;
import org.java_websocket.handshake.ServerHandshake;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.ZoneId;
import java.util.Collection;
import java.util.LinkedList;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import static com.newrelic.agent.security.intcodeagent.logging.IAgentConstants.ERROR_OCCURED_WHILE_TRYING_TO_CONNECT_TO_WSOCKET;

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
    public static final String INCOMING_CONTROL_COMMAND_S = "Incoming control command : %s";

    private static WSClient instance;

    private WebSocketImpl connection = null;


    private SSLContext createSSLContext() throws Exception {
        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        Collection<X509Certificate> caCerts = new LinkedList<>();
        // Get the jvm default trust chain first.
        Set<X509Certificate> defaultTrustCerts = CustomTrustStoreManagerUtils.getTrustedCerts();
        if(defaultTrustCerts != null) {
            caCerts.addAll(defaultTrustCerts);
        }
        // Add NR specific certs to trust store
        try (InputStream is = new BufferedInputStream(getCaBundleStream())) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            while (is.available() > 0) {
                try {
                    caCerts.add((X509Certificate) cf.generateCertificate(is));
                } catch (Exception e) {
                    logger.log(LogLevel.SEVERE,
                            "Unable to generate ca certificate. Verify the certificate format. Will not process further certs.", e, WSClient.class.getName());
                    break;
                }
            }
        }

        logger.log(caCerts.size() > 0 ? LogLevel.INFO : LogLevel.SEVERE,
                String.format("Found %s certificates.", caCerts.size()), WSClient.class.getName());
        // Initialize the keystore
        keystore.load(null, null);

        int i = 1;
        for (X509Certificate caCert : caCerts) {
            if (caCert != null) {
                String alias = "nr_csec_ca_bundle_" + i;
                keystore.setCertificateEntry(alias, caCert);
                logger.log(LogLevel.FINER, String.format("Installed CA certificate %s(serial %s) for subjects : %s - %s",
                        alias, caCert.getSerialNumber(), caCert.getSubjectDN().getName(),
                        caCert.getSubjectAlternativeNames()), WSClient.class.getName());
            }
            i++;
        }
        TrustManagerFactory trustManagerFactory = TrustManagerFactory
                .getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagerFactory.init(keystore);

        SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
        sslContext.init(null, trustManagerFactory.getTrustManagers(), null);
        return sslContext;
    }

    private InputStream getCaBundleStream() throws IOException {
        InputStream inputStream;
        String caBundlePath = NewRelic.getAgent().getConfig().getValue(IUtilConstants.NR_SECURITY_CA_BUNDLE_PATH);
        if (StringUtils.isNotBlank(caBundlePath)) {
            inputStream = Files.newInputStream(Paths.get(caBundlePath));
        } else {
            inputStream = CommonUtils.getResourceStreamFromAgentJar("nr-custom-ca.pem");
        }
        return inputStream;
    }

    private WSClient() throws URISyntaxException {
        super(new URI(AgentConfig.getInstance().getConfig().getK2ServiceInfo().getValidatorServiceEndpointURL()),
                new Draft_6455(), null, (int) TimeUnit.SECONDS.toMillis(15));
        this.setTcpNoDelay(true);
        this.setConnectionLostTimeout(30);
        this.addHeader("NR-CSEC-CONNECTION-TYPE", "LANGUAGE_COLLECTOR");
        this.addHeader("NR-AGENT-RUN-TOKEN", AgentInfo.getInstance().getLinkingMetadata().getOrDefault(INRSettingsKey.AGENT_RUN_ID_LINKING_METADATA, StringUtils.EMPTY));
        this.addHeader("NR-LICENSE-KEY", AgentConfig.getInstance().getConfig().getCustomerInfo().getApiAccessorToken());
        this.addHeader("NR-CSEC-VERSION", AgentInfo.getInstance().getBuildInfo().getCollectorVersion());
        this.addHeader("NR-CSEC-COLLECTOR-TYPE", "JAVA");
        this.addHeader("NR-CSEC-BUILD-NUMBER", AgentInfo.getInstance().getBuildInfo().getBuildNumber());
        this.addHeader("NR-CSEC-MODE", AgentConfig.getInstance().getGroupName());
        this.addHeader("NR-CSEC-APP-UUID", AgentInfo.getInstance().getApplicationUUID());
        this.addHeader("NR-CSEC-JSON-VERSION", AgentInfo.getInstance().getBuildInfo().getJsonVersion());
        this.addHeader("NR-ACCOUNT-ID", AgentConfig.getInstance().getConfig().getCustomerInfo().getAccountId());
        this.addHeader("NR-CSEC-IAST-DATA-TRANSFER-MODE", "PULL");
        if (StringUtils.startsWithIgnoreCase(AgentConfig.getInstance().getConfig().getK2ServiceInfo().getValidatorServiceEndpointURL(), "wss:")) {
            try {
                this.setSocketFactory(createSSLContext().getSocketFactory());
            } catch (Exception e) {
                logger.log(LogLevel.SEVERE, String.format("Error creating socket factory message : %s , cause : %s", e.getMessage(), e.getCause()), WSClient.class.getName());
                logger.log(LogLevel.FINER, "Error creating socket factory", e, WSClient.class.getName());
            }
        }
    }

    @Override
    public void addHeader(String key, String value) {
        String printValue = value;
        if(StringUtils.equals(key, "NR-LICENSE-KEY")) {
            printValue = StringUtils.substring(value, 0,4) + "-******-" +
                    StringUtils.substring(value, value.length()-7);
        }
        logger.log(LogLevel.INFO, String.format("Adding WS connection header: %s -> %s", key, printValue),
                WSClient.class.getName());
        super.addHeader(key, value);
    }

    /**
     * Connects to K2 intcode over a websocket channel with the configuration provided in the constructor itself.
     *
     * @throws InterruptedException
     */
    public void openConnection() throws InterruptedException {
        connectBlocking(30, TimeUnit.SECONDS);
        WebSocket conn = getConnection();
        if (conn instanceof WebSocketImpl) {
            this.connection = (WebSocketImpl) conn;
        }
    }

    @Override
    public void onOpen(ServerHandshake handshakedata) {
        logger.logInit(LogLevel.INFO, String.format(IAgentConstants.INIT_WS_CONNECTION, AgentConfig.getInstance().getConfig().getK2ServiceInfo().getValidatorServiceEndpointURL()),
                WSClient.class.getName());
        logger.logInit(LogLevel.INFO, String.format(IAgentConstants.SENDING_APPLICATION_INFO_ON_WS_CONNECT, AgentInfo.getInstance().getApplicationInfo()), WSClient.class.getName());
        RestRequestThreadPool.getInstance().resetIASTProcessing();
        DispatcherPool.getInstance().reset();
        EventSendPool.getInstance().reset();
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
            if (logger.isLogLevelEnabled(LogLevel.FINEST)) {
                logger.log(LogLevel.FINEST, String.format(INCOMING_CONTROL_COMMAND_S, message),
                        this.getClass().getName());
            }
            ControlCommandProcessor.processControlCommand(message, System.currentTimeMillis());
        } catch (Throwable e) {
            logger.log(LogLevel.SEVERE, UNABLE_TO_PROCESS_INCOMING_MESSAGE + message + DUE_TO_ERROR, e,
                    WSClient.class.getName());
        }
    }

    @Override
    public void onClose(int code, String reason, boolean remote) {
        logger.log(LogLevel.WARNING, CONNECTION_CLOSED_BY + (remote ? REMOTE_PEER : LOCAL) + CODE + code
                + REASON + reason, WSClient.class.getName());
        if (code == CloseFrame.NEVER_CONNECTED) {
            return;
        }
        WSUtils.getInstance().setConnected(false);
        if (code == CloseFrame.POLICY_VALIDATION) {
            WSReconnectionST.cancelTask(true);
        }
    }

    @Override
    public void onError(Exception ex) {
        logger.logInit(LogLevel.SEVERE, String.format(IAgentConstants.WS_CONNECTION_UNSUCCESSFUL_INFO, AgentConfig
                                .getInstance().getConfig().getK2ServiceInfo().getValidatorServiceEndpointURL(),
                        ex.toString(), ex.getCause()),
                WSClient.class.getName());
        logger.log(LogLevel.FINER, String.format(IAgentConstants.WS_CONNECTION_UNSUCCESSFUL, AgentConfig.getInstance().getConfig().getK2ServiceInfo().getValidatorServiceEndpointURL()),
                ex,
                WSClient.class.getName());
    }

    @Override
    public void send(String text) {
        if (StringUtils.isBlank(text)) {
            return;
        }
        if (this.isOpen()) {
            logger.log(LogLevel.FINER, SENDING_EVENT + text, WSClient.class.getName());
            super.send(text);
        } else {
            logger.log(LogLevel.FINER, UNABLE_TO_SEND_EVENT + text, WSClient.class.getName());
        }
    }

    @Override
    public void onWebsocketPing(WebSocket conn, Framedata f) {
        logger.log(LogLevel.FINER, String.format(RECEIVED_PING_AT_S_SENDING_PONG, Instant.now().atZone(ZoneId.of("UTC")).toLocalTime()), WSClient.class.getName());
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
        logger.log(LogLevel.INFO, RECONNECTING_TO_IC,
                WSClient.class.getName());
        if (instance != null && instance.isOpen()) {
            instance.closeBlocking();
        }
        instance = new WSClient();
        instance.openConnection();
        return instance;
    }

    public static void shutDownWSClient() {
        logger.log(LogLevel.WARNING, "Disconnecting WS client forced by APM",
                WSClient.class.getName());
        WSUtils.getInstance().setConnected(false);
        RestRequestThreadPool.getInstance().resetIASTProcessing();
        if (instance != null) {
            instance.close(CloseFrame.ABNORMAL_CLOSE, "Client disconnecting forced by APM");
        }
    }

}
