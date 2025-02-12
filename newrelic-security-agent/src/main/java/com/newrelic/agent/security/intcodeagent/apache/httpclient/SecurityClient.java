package com.newrelic.agent.security.intcodeagent.apache.httpclient;

import com.newrelic.agent.security.AgentConfig;
import com.newrelic.agent.security.AgentInfo;
import com.newrelic.agent.security.instrumentator.dispatcher.DispatcherPool;
import com.newrelic.agent.security.instrumentator.httpclient.RestRequestThreadPool;
import com.newrelic.agent.security.instrumentator.utils.INRSettingsKey;
import com.newrelic.agent.security.intcodeagent.websocket.EventSendPool;
import com.newrelic.agent.security.intcodeagent.websocket.EventSender;
import com.newrelic.api.agent.security.instrumentation.helpers.GrpcClientRequestReplayHelper;
import com.newrelic.api.agent.security.utils.ConnectionException;
import com.newrelic.agent.security.intcodeagent.filelogging.FileLoggerThreadPool;
import com.newrelic.agent.security.util.IUtilConstants;
import com.newrelic.api.agent.NewRelic;
import com.newrelic.api.agent.security.schema.http.ReadResult;
import com.newrelic.api.agent.security.schema.http.RequestLayout;
import com.newrelic.api.agent.security.utils.SecurityConnection;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import org.apache.commons.lang3.StringUtils;
import org.json.simple.JSONStreamAware;
import org.json.simple.JSONValue;

import javax.net.ssl.SSLContext;
import java.io.*;
import java.lang.management.ManagementFactory;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.GZIPOutputStream;

public class SecurityClient implements SecurityConnection {

    private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();
    private final ApacheHttpClientWrapper httpClient;
    private boolean connected = false;
    private final Map<String, String> headers = new HashMap<>();
    private final String URL = NewRelic.getAgent().getConfig().getValue("security.validator_service_url", "wss://csec.nr-data.net");

    public static final String DEFLATE_ENCODING = "deflate";
    public static final String GZIP_ENCODING = "gzip";
    private static final int COMPRESSION_LEVEL = Deflater.DEFAULT_COMPRESSION;

    public static final String PROXY_HOST = "proxy_host";
    public static final String PROXY_PASS = "proxy_password";
    public static final String PROXY_PORT = "proxy_port";
    public static final String PROXY_SCHEME = "proxy_scheme";
    public static final String PROXY_USER = "proxy_user";

    public static final ReadResult unsupportedContent = new ReadResult(500, "Unsupported content type");
    private boolean reconnecting = false;

    private SecurityClient() {
        SSLContext sslContext = ApacheSSLManager.createSSLContext(NewRelic.getAgent().getConfig().getValue(IUtilConstants.NR_SECURITY_CA_BUNDLE_PATH));
        String proxyHost = NewRelic.getAgent().getConfig().getValue(PROXY_HOST, null);
        Integer proxyPort = NewRelic.getAgent().getConfig().getValue(PROXY_PORT, 8080);
        String proxyScheme = NewRelic.getAgent().getConfig().getValue(PROXY_SCHEME, "https");
        String proxyUser = NewRelic.getAgent().getConfig().getValue(PROXY_USER, null);
        String proxyPass = NewRelic.getAgent().getConfig().getValue(PROXY_PASS, null);
        ApacheProxyManager proxyManager = new ApacheProxyManager(
                proxyHost, proxyPort, proxyScheme,
                proxyUser, proxyPass);
        setConnectionHeaders();
        httpClient = new ApacheHttpClientWrapper(proxyManager, sslContext, 30000);
    }

    private void setConnectionHeaders() {
        this.headers.put("NR-CSEC-CONNECTION-TYPE", "LANGUAGE_COLLECTOR");
        this.headers.put("NR-AGENT-RUN-TOKEN", AgentInfo.getInstance().getLinkingMetadata().getOrDefault(INRSettingsKey.AGENT_RUN_ID_LINKING_METADATA, StringUtils.EMPTY));
        this.headers.put("NR-CSEC-ENTITY-GUID", AgentInfo.getInstance().getLinkingMetadata().getOrDefault(INRSettingsKey.NR_ENTITY_GUID, StringUtils.EMPTY));
        this.headers.put("NR-CSEC-ENTITY-NAME", AgentInfo.getInstance().getLinkingMetadata().getOrDefault(INRSettingsKey.ENTITY_NAME, StringUtils.EMPTY));
        this.headers.put("NR-LICENSE-KEY", AgentConfig.getInstance().getConfig().getCustomerInfo().getApiAccessorToken());
        this.headers.put("NR-CSEC-VERSION", AgentInfo.getInstance().getBuildInfo().getCollectorVersion());
        this.headers.put("NR-CSEC-COLLECTOR-TYPE", "JAVA");
        this.headers.put("NR-CSEC-BUILD-NUMBER", AgentInfo.getInstance().getBuildInfo().getBuildNumber());
        this.headers.put("NR-CSEC-MODE", AgentConfig.getInstance().getGroupName());
        this.headers.put("NR-CSEC-APP-UUID", AgentInfo.getInstance().getApplicationUUID());
        this.headers.put("NR-CSEC-JSON-VERSION", AgentInfo.getInstance().getBuildInfo().getJsonVersion());
        this.headers.put("NR-ACCOUNT-ID", AgentConfig.getInstance().getConfig().getCustomerInfo().getAccountId());
        this.headers.put("NR-CSEC-IAST-DATA-TRANSFER-MODE", "PULL");
        this.headers.put("NR-CSEC-IGNORED-VUL-CATEGORIES", AgentConfig.getInstance().getAgentMode().getSkipScan().getIastDetectionCategory().getDisabledCategoriesCSV());
        this.headers.put("NR-CSEC-PROCESS-START-TIME", String.valueOf(ManagementFactory.getRuntimeMXBean().getStartTime()));
        this.headers.put("NR-CSEC-IAST-TEST-IDENTIFIER", AgentConfig.getInstance().getScanControllers().getIastTestIdentifier());
        this.headers.put("NR-CSEC-IAST-SCAN-INSTANCE-COUNT", String.valueOf(AgentConfig.getInstance().getScanControllers().getScanInstanceCount()));
    }

    private static final class InstanceHolder {
        static final SecurityClient instance = new SecurityClient();
    }

    public static SecurityClient getInstance() {
        return InstanceHolder.instance;
    }

    public void setConnected(boolean connected) {
        this.connected = connected;
        AgentInfo.getInstance().agentStatTrigger(false);
    }

    public boolean isConnected() {
        return this.connected;
    }

    @Override
    public boolean isReconnecting() {
        return this.reconnecting;
    }

    @Override
    public void setReconnecting(boolean isReconnecting) {
        this.reconnecting = isReconnecting;
    }

    @Override
    public ReadResult send(Object message, String api) throws ConnectionException {
        if(message instanceof JSONStreamAware) {
            return send((JSONStreamAware) message, api);
        } else {
            logger.log(LogLevel.WARNING, String.format("Unsupported message type %s", message.getClass().getName()), ApacheHttpClientWrapper.class.getName());
            logger.log(LogLevel.FINEST, String.format("Unsupported message type %s : %s", message.getClass().getName(), message), ApacheHttpClientWrapper.class.getName());
            return unsupportedContent;
        }
    }

    public ReadResult send(JSONStreamAware message, String api) throws ApacheHttpExceptionWrapper {
        RequestLayout requestLayout = null;
        try {
            requestLayout = getRequestConfigurations(api);
            requestLayout.setEndpoint(URL);
            logger.log(LogLevel.FINEST, "Request configurations for API: " + api + " : " + requestLayout.getPath() + " body : "+message, ApacheHttpClientWrapper.class.getName());
        } catch (Exception e){
            logger.log(LogLevel.WARNING, "Error while getting request configurations for API: " + api, ApacheHttpClientWrapper.class.getName());
            logger.postLogMessageIfNecessary(LogLevel.WARNING, "Error while getting request configurations for API: " + api, e, ApacheHttpClientWrapper.class.getName());
            return null;
        }
        try {
            byte[] body = null;
            if(message != null) {
                body = writeData(requestLayout.getContentEncoding(), message);
            }
            ReadResult result = httpClient.execute(requestLayout, null, null, headers, body);
            logger.log(LogLevel.FINEST, "Response from " + api + ": " + result.getStatusCode() + " body: "+result.getResponseBody(), ApacheHttpClientWrapper.class.getName());
            return result;
        } catch (Exception e) {
            throw new ApacheHttpExceptionWrapper(e.getMessage(), e);
        }
    }

    @Override
    public void close(String message) {
        cleanIASTState();
        httpClient.shutdown();
    }

    private static void cleanIASTState() {
        RestRequestThreadPool.getInstance().resetIASTProcessing();
        GrpcClientRequestReplayHelper.getInstance().resetIASTProcessing();
        RestRequestThreadPool.getInstance().getRejectedIds().clear();
        GrpcClientRequestReplayHelper.getInstance().getRejectedIds().clear();
        DispatcherPool.getInstance().reset();
        EventSendPool.getInstance().reset();
    }

    @Override
    public void ping() {
        try {
            ReadResult result = send(null, "ping");
            if(result != null && result.getStatusCode() == 200) {
                setConnected(true);
                setReconnecting(false);
            } else {
                setConnected(false);
                setReconnecting(true);
                ReconnectionST.getInstance().cancelTask();
                ReconnectionST.getInstance().submitNewTaskSchedule();
            }
        } catch (ConnectionException e) {
            logger.log(LogLevel.SEVERE, "Error while pinging the security service: "+ e.getMessage(), ApacheHttpClientWrapper.class.getName());
            logger.log(LogLevel.FINEST, "Error while pinging the security service: ", e, ApacheHttpClientWrapper.class.getName());
            setConnected(false);
        }
    }

    @Override
    public void reconnectIfRequired() {}

    public String getURL() {
        return URL;
    }

    private RequestLayout getRequestConfigurations(String api) throws ApacheHttpExceptionWrapper {
        if(StringUtils.isBlank(api)){
            throw new ApacheHttpExceptionWrapper("Unsupported API");
        }
        return CommunicationApis.get(api);
    }

    private byte[] writeData(String encoding, JSONStreamAware params) throws IOException {
        ByteArrayOutputStream outStream = new ByteArrayOutputStream();
        try (
                OutputStream os = getOutputStream(outStream, encoding);
                Writer out = new OutputStreamWriter(os, StandardCharsets.UTF_8)
        ) {
            JSONValue.writeJSONString(params, out);
            out.flush();
        }
        return outStream.toByteArray();
    }

    private OutputStream getOutputStream(OutputStream out, String encoding) throws IOException {
        if (DEFLATE_ENCODING.equals(encoding)) {
            return new DeflaterOutputStream(out, new Deflater(COMPRESSION_LEVEL));
        } else if (GZIP_ENCODING.equals(encoding)) {
            return new GZIPOutputStream(out);
        } else {
            return out;
        }
    }
}
