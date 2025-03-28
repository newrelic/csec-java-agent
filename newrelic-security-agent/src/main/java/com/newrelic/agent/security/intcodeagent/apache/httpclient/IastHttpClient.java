package com.newrelic.agent.security.intcodeagent.apache.httpclient;

import com.newrelic.agent.security.instrumentator.httpclient.RestRequestThreadPool;
import com.newrelic.agent.security.intcodeagent.filelogging.FileLoggerThreadPool;
import com.newrelic.agent.security.intcodeagent.models.FuzzRequestBean;
import com.newrelic.api.agent.security.instrumentation.helpers.AppServerInfoHelper;
import com.newrelic.api.agent.security.schema.AppServerInfo;
import com.newrelic.api.agent.security.schema.HttpRequest;
import com.newrelic.api.agent.security.schema.ServerConnectionConfiguration;
import com.newrelic.api.agent.security.schema.http.ReadResult;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URISyntaxException;
import java.util.*;

public class IastHttpClient {

    public static final String ENDPOINT_HTTP_LOCALHOST_S = "http://localhost:%s";
    public static final String ENDPOINT_HTTPS_LOCALHOST_S = "https://localhost:%s";

    private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();


    private final ApacheHttpClientWrapper httpClient;
    private boolean connected = false;

    private IastHttpClient() {
        httpClient = new ApacheHttpClientWrapper(30000);
    }

    public void setConnected(boolean connected) {
        this.connected = connected;
    }

    public boolean isConnected() {
        return this.connected;
    }

    private static final class InstanceHolder {
        static final IastHttpClient instance = new IastHttpClient();
    }

    public static IastHttpClient getInstance() {
        return InstanceHolder.instance;
    }

    public void replay(Map<Integer, ServerConnectionConfiguration> applicationConnectionConfig, FuzzRequestBean httpRequest, String fuzzRequestId) {
        List<String> endpoints = getAllEndpoints(applicationConnectionConfig);
        logger.log(LogLevel.FINEST, String.format("Replaying request %s with endpoints %s", fuzzRequestId, endpoints), IastHttpClient.class.getName());
        if(endpoints.isEmpty()) {
            throw new IllegalArgumentException("No endpoints found for replaying request " + fuzzRequestId);
        }
        for (String endpoint : endpoints) {
            try {
                ReadResult result = httpClient.execute(httpRequest, endpoint, fuzzRequestId);
                RestRequestThreadPool.getInstance().getProcessedIds().putIfAbsent(fuzzRequestId, new HashSet<>());
                if(200 <= result.getStatusCode() && result.getStatusCode() < 300) {
                    logger.log(LogLevel.FINEST, "Replay Request " + fuzzRequestId + " passed with status code " + result.getStatusCode() + " and response: " + result.getResponseBody(), IastHttpClient.class.getName());
                    break;
                } else {
                    logger.log(LogLevel.FINE, "Replay Request " + fuzzRequestId + " failed with status code " + result.getStatusCode() + " and reason: " + result.getResponseBody(), IastHttpClient.class.getName());
                    logger.postLogMessageIfNecessary(LogLevel.FINE, "Request " + fuzzRequestId + " failed with status code " + result.getStatusCode() + " and reason: " + result.getResponseBody(), null, IastHttpClient.class.getName());
                }
            } catch (Exception e) {
                String message = "Error while replaying control command %s with message : %s";
                logger.log(LogLevel.FINE, String.format(message, fuzzRequestId, e.getMessage()), IastHttpClient.class.getName());
                logger.postLogMessageIfNecessary(LogLevel.WARNING, String.format(message, fuzzRequestId, e.getMessage()), e, ApacheHttpClientWrapper.class.getName());
            }
        }
    }

    public void tryToEstablishApplicationEndpoint(HttpRequest request) {

        int serverPort = request.getServerPort();
        if(serverPort > 0){
            Map<String, String> endpoints = prepareEndpoints(serverPort);
            for (Map.Entry<String, String> endpoint : endpoints.entrySet()) {
                try {
                    ReadResult result = httpClient.execute(request, endpoint.getValue(), null, true);
                    int statusCode = result.getStatusCode();
                    if ((statusCode >= 200 && statusCode < 300) ||
                            statusCode == 401 || statusCode == 402 ||
                            statusCode == 406 || statusCode == 409) {
                        ServerConnectionConfiguration serverConnectionConfiguration = new ServerConnectionConfiguration(serverPort, endpoint.getKey(), endpoint.getValue(), true);
                        AppServerInfo appServerInfo = AppServerInfoHelper.getAppServerInfo();
                        appServerInfo.getConnectionConfiguration().put(serverPort, serverConnectionConfiguration);
                        logger.postLogMessageIfNecessary(LogLevel.INFO, String.format("Confirmed endpoint for this application is %s", serverConnectionConfiguration.getEndpoint()), null, this.getClass().getName());
                        logger.log(LogLevel.FINER, String.format("Setting up new connection configuration for port %s : %s", serverPort, serverConnectionConfiguration.getEndpoint()), IastHttpClient.class.getName());
                        return;
                    }
                } catch (ApacheHttpExceptionWrapper | IOException | URISyntaxException e) {
                    String message = "Error while executing request for connection endpoint detection %s message : %s";
                    logger.log(LogLevel.FINE, String.format(message, request, e.getMessage()), IastHttpClient.class.getName());
                    logger.postLogMessageIfNecessary(LogLevel.WARNING, String.format(message, request, e.getMessage()), e, ApacheHttpClientWrapper.class.getName());
                }
            }
        }

    }

    private static Map<String, String> prepareEndpoints(int serverPort) {
        Map<String, String> endpoints = new HashMap<>();
        endpoints.put("http", String.format(ENDPOINT_HTTP_LOCALHOST_S, serverPort));
        endpoints.put("https", String.format(ENDPOINT_HTTPS_LOCALHOST_S, serverPort));
        return endpoints;
    }

    private List<String> getAllEndpoints(Map<Integer, ServerConnectionConfiguration> applicationConnectionConfig) {
        List<String> endpoints = new ArrayList<>();
        for (Map.Entry<Integer, ServerConnectionConfiguration> connectionConfig : applicationConnectionConfig.entrySet()) {
            ServerConnectionConfiguration connectionConfiguration = connectionConfig.getValue();
            if(connectionConfig.getValue().isConfirmed()){
                endpoints.add(connectionConfiguration.getEndpoint());
            }
        }
        return endpoints;
    }

}
