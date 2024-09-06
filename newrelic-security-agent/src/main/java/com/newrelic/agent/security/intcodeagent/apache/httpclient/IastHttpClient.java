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

import java.io.IOException;
import java.net.URISyntaxException;
import java.util.*;

public class IastHttpClient {

    public static final String ENDPOINT_HTTP_LOCALHOST_S = "http://localhost:%s";
    public static final String ENDPOINT_HTTPS_LOCALHOST_S = "https://localhost:%s";

    private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();


    private ApacheHttpClientWrapper httpClient;

    private IastHttpClient() {
        httpClient = new ApacheHttpClientWrapper(30000);
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
        for (String endpoint : endpoints) {
            try {
                ReadResult result = httpClient.execute(httpRequest, endpoint);
                RestRequestThreadPool.getInstance().getProcessedIds().putIfAbsent(fuzzRequestId, new HashSet<>());
                if(200 <= result.getStatusCode() && result.getStatusCode() < 300) {
                    break;
                }
            } catch (IOException | URISyntaxException e) {
                logger.log(LogLevel.FINE, "Error while replaying request", e, IastHttpClient.class.getName());
            } catch (Exception e) {
                logger.log(LogLevel.WARNING, "Error while replaying request", e, IastHttpClient.class.getName());
            }
        }
    }

    public void tryToEstablishApplicationEndpoint(HttpRequest request) {

        int serverPort = request.getServerPort();
        if(serverPort > 0){
            Map<String, String> endpoints = prepareEndpoints(serverPort);
            for (Map.Entry<String, String> endpoint : endpoints.entrySet()) {
                try {
                    ReadResult result = httpClient.execute(request, endpoint.getValue(), true);
                    if(result.getStatusCode() >= 200 && result.getStatusCode() <= 500) {
                        ServerConnectionConfiguration serverConnectionConfiguration = new ServerConnectionConfiguration(serverPort, endpoint.getKey());
                        AppServerInfo appServerInfo = AppServerInfoHelper.getAppServerInfo();
                        appServerInfo.getConnectionConfiguration().put(serverPort, serverConnectionConfiguration);
                        serverConnectionConfiguration.setEndpoint(endpoint.getValue());
                        serverConnectionConfiguration.setConfirmed(true);
                        return;
                    }
                } catch (IOException | URISyntaxException e) {
                    logger.log(LogLevel.FINEST, "Error while trying to establish application endpoint ", e, IastHttpClient.class.getName());
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
