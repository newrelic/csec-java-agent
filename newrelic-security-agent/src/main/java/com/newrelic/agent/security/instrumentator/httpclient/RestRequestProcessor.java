package com.newrelic.agent.security.instrumentator.httpclient;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.newrelic.agent.security.AgentInfo;
import com.newrelic.agent.security.instrumentator.os.OsVariablesInstance;
import com.newrelic.agent.security.instrumentator.utils.CallbackUtils;
import com.newrelic.agent.security.intcodeagent.filelogging.FileLoggerThreadPool;
import com.newrelic.agent.security.intcodeagent.logging.IAgentConstants;
import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.schema.ServerConnectionConfiguration;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import com.newrelic.agent.security.intcodeagent.models.FuzzRequestBean;
import com.newrelic.agent.security.intcodeagent.models.javaagent.IntCodeControlCommand;
import com.newrelic.agent.security.intcodeagent.websocket.WSUtils;
import com.newrelic.api.agent.security.instrumentation.helpers.GrpcClientRequestReplayHelper;
import com.newrelic.api.agent.security.schema.ControlCommandDto;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import org.apache.commons.lang3.StringUtils;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;

/**
 * Request repeater for IAST
 */
public class RestRequestProcessor implements Callable<Boolean> {

    public static final String NR_CSEC_VALIDATOR_HOME_TMP = "/{{NR_CSEC_VALIDATOR_HOME_TMP}}";
    public static final String NR_CSEC_VALIDATOR_HOME_TMP_URL_ENCODED = "%2F%7B%7BNR_CSEC_VALIDATOR_HOME_TMP%7D%7D";

    public static final String ERROR_IN_FUZZ_REQUEST_GENERATION = "Error in fuzz request generation %s";

    public static final String ERROR_WHILE_PROCESSING_FUZZING_REQUEST_S = "Error while processing fuzzing request : %s";

    public static final String JSON_PARSING_ERROR_WHILE_PROCESSING_FUZZING_REQUEST_S = "JSON parsing error while processing fuzzing request : %s";
    private static final int MAX_REPETITION = 3;
    public static final String ENDPOINT_LOCALHOST_S = "%s://localhost:%s";
    private IntCodeControlCommand controlCommand;

    private int repeatCount;

    private ObjectMapper objectMapper = new ObjectMapper();

    private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

    public RestRequestProcessor(IntCodeControlCommand controlCommand, int repeatCount) {
        this.controlCommand = controlCommand;
        this.repeatCount = repeatCount;
    }


    /**
     * Does the request replay in IAST mode.
     */
    @Override
    public Boolean call() throws InterruptedException {
        if (controlCommand.getArguments().size() < 2 ) {
            return true;
        }
        if( !AgentInfo.getInstance().isAgentActive()) {
            return false;
        }

        FuzzRequestBean httpRequest = null;
        try {
            if (WSUtils.getInstance().isReconnecting()) {
                   synchronized (WSUtils.getInstance()) {
                    RestRequestThreadPool.getInstance().isWaiting().set(true);
                    GrpcClientRequestReplayHelper.getInstance().isWaiting().set(true);
                    WSUtils.getInstance().wait();
                    RestRequestThreadPool.getInstance().isWaiting().set(false);
                    GrpcClientRequestReplayHelper.getInstance().isWaiting().set(false);
                }
            }
            String req = StringUtils.replace(controlCommand.getArguments().get(0), NR_CSEC_VALIDATOR_HOME_TMP, OsVariablesInstance.getInstance().getOsVariables().getTmpDirectory());
            req = StringUtils.replace(req, NR_CSEC_VALIDATOR_HOME_TMP_URL_ENCODED, CallbackUtils.urlEncode(OsVariablesInstance.getInstance().getOsVariables().getTmpDirectory()));

            httpRequest = objectMapper.readValue(req, FuzzRequestBean.class);
            httpRequest.getHeaders().put(GenericHelper.CSEC_PARENT_ID, controlCommand.getId());
            if (httpRequest.getIsGrpc()){
                GrpcClientRequestReplayHelper.getInstance().getPendingIds().add(controlCommand.getId());
                GrpcClientRequestReplayHelper.getInstance().removeFromProcessedCC(controlCommand.getId());
            } else {
                RestRequestThreadPool.getInstance().getPendingIds().add(controlCommand.getId());
                RestRequestThreadPool.getInstance().removeFromProcessedCC(controlCommand.getId());
            }
            httpRequest.setReflectedMetaData(controlCommand.getReflectedMetaData());

            if (httpRequest.getIsGrpc()){
                List<String> payloadList = new ArrayList<>();
                try{
                    List<?> list = objectMapper.readValue(String.valueOf(httpRequest.getBody()), List.class);
                    for (Object o : list) {
                        payloadList.add(objectMapper.writeValueAsString(o));
                    }
                } catch (Throwable e) {
                    NewRelicSecurity.getAgent().reportIASTScanFailure(null, null,
                            e, RequestUtils.extractNRCsecFuzzReqHeader(httpRequest), controlCommand.getId(),
                            String.format(IAgentConstants.FAILURE_WHILE_GRPC_REQUEST_BODY_CONVERSION, httpRequest.getBody()));
                    logger.log(LogLevel.FINEST, String.format(ERROR_IN_FUZZ_REQUEST_GENERATION, e.getMessage()), RestRequestProcessor.class.getSimpleName());
                }
                MonitorGrpcFuzzFailRequestQueueThread.submitNewTask();
                GrpcClientRequestReplayHelper.getInstance().addToRequestQueue(new ControlCommandDto(controlCommand.getId(), httpRequest, payloadList));
            } else {
                boolean postSSL = false;
                List<String> endpoints = prepareAllEndpoints(NewRelicSecurity.getAgent().getApplicationConnectionConfig(), httpRequest);
                logger.log(LogLevel.FINER, String.format("Endpoints to fire : %s", endpoints), RestRequestProcessor.class.getSimpleName());
                if (endpoints.isEmpty()){
                    endpoints = prepareAllEndpoints(httpRequest);
                    logger.log(LogLevel.FINER, String.format("Endpoints to fire in empty: %s", endpoints), RestRequestProcessor.class.getSimpleName());
                    postSSL = true;
                }
                RestClient.getInstance().fireRequest(httpRequest, endpoints, repeatCount + endpoints.size() -1, controlCommand.getId());
            }
            return true;
        } catch (JsonProcessingException e){
            NewRelicSecurity.getAgent().reportIASTScanFailure(null, null,
                    e, null, controlCommand.getId(),
                    String.format(JSON_PARSING_ERROR_WHILE_PROCESSING_FUZZING_REQUEST_S, controlCommand.getArguments().get(0)));

            logger.log(LogLevel.SEVERE,
                    String.format(JSON_PARSING_ERROR_WHILE_PROCESSING_FUZZING_REQUEST_S, controlCommand.getArguments().get(0)),
                    e, RestRequestProcessor.class.getName());
            logger.postLogMessageIfNecessary(LogLevel.SEVERE,
                    String.format(JSON_PARSING_ERROR_WHILE_PROCESSING_FUZZING_REQUEST_S, controlCommand.getId()), e, RestRequestProcessor.class.getName());
            RestRequestThreadPool.getInstance().getProcessedIds().putIfAbsent(controlCommand.getId(), new HashSet<>());
        } catch (Throwable e) {
            NewRelicSecurity.getAgent().reportIASTScanFailure(null, null,
                    e, RequestUtils.extractNRCsecFuzzReqHeader(httpRequest), controlCommand.getId(),
                    String.format(JSON_PARSING_ERROR_WHILE_PROCESSING_FUZZING_REQUEST_S, controlCommand.getArguments().get(0)));

            logger.log(LogLevel.SEVERE,
                    String.format(ERROR_WHILE_PROCESSING_FUZZING_REQUEST_S, controlCommand.getArguments().get(0)),
                    e, RestRequestProcessor.class.getName());
            logger.postLogMessageIfNecessary(LogLevel.SEVERE,
                    String.format(ERROR_WHILE_PROCESSING_FUZZING_REQUEST_S, controlCommand.getId()),
                    e, RestRequestProcessor.class.getName());
            RestRequestThreadPool.getInstance().getProcessedIds().putIfAbsent(controlCommand.getId(), new HashSet<>());
            throw e;
        }
        return true;
    }

    private List<String> prepareAllEndpoints(FuzzRequestBean httpRequest) {
        List<String> endpoitns = new ArrayList<>();
        endpoitns.add(String.format(ENDPOINT_LOCALHOST_S, httpRequest.getProtocol(), httpRequest.getServerPort()));
        endpoitns.add(String.format(ENDPOINT_LOCALHOST_S, toggleProtocol(httpRequest.getProtocol()), httpRequest.getServerPort()));
        return endpoitns;
    }

    private List<String> prepareAllEndpoints(Map<Integer, ServerConnectionConfiguration> applicationConnectionConfig, FuzzRequestBean httpRequest) {
        List<String> endpoints = new ArrayList<>();
        for (Map.Entry<Integer, ServerConnectionConfiguration> connectionConfig : applicationConnectionConfig.entrySet()) {
            ServerConnectionConfiguration connectionConfiguration = connectionConfig.getValue();
            if(!connectionConfig.getValue().isConfirmed()){
                if (RequestUtils.refineEndpoints(httpRequest, String.format(ENDPOINT_LOCALHOST_S, connectionConfiguration.getProtocol(), connectionConfiguration.getPort()))) {
                    updateServerConnectionConfiguration(connectionConfiguration, connectionConfiguration.getProtocol());
                    endpoints.add(connectionConfiguration.getEndpoint());
                } else if (RequestUtils.refineEndpoints(httpRequest, String.format(ENDPOINT_LOCALHOST_S, toggleProtocol(connectionConfiguration.getProtocol()), connectionConfiguration.getPort()))) {
                    updateServerConnectionConfiguration(connectionConfiguration, toggleProtocol(connectionConfiguration.getProtocol()));
                    endpoints.add(connectionConfiguration.getEndpoint());
                }
            } else {
                endpoints.add(connectionConfiguration.getEndpoint());
            }
        }
        return endpoints;
    }

    private void updateServerConnectionConfiguration(ServerConnectionConfiguration connectionConfiguration, String protocol) {
        connectionConfiguration.setEndpoint(String.format(ENDPOINT_LOCALHOST_S, protocol, connectionConfiguration.getPort()));
        connectionConfiguration.setProtocol(protocol);
        connectionConfiguration.setConfirmed(true);
    }

    private String toggleProtocol(String value) {
        return StringUtils.equalsAnyIgnoreCase(value, "https")? "http": "https";
    }

    public static void processControlCommand(IntCodeControlCommand command) {
        RestRequestThreadPool.getInstance().executor
                .submit(new RestRequestProcessor(command, MAX_REPETITION));
    }

    public IntCodeControlCommand getControlCommand() {
        return controlCommand;
    }
}
