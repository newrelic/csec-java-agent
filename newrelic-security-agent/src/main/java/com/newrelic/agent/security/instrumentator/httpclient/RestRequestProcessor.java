package com.newrelic.agent.security.instrumentator.httpclient;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.newrelic.agent.security.AgentInfo;
import com.newrelic.agent.security.instrumentator.os.OsVariablesInstance;
import com.newrelic.agent.security.instrumentator.utils.CallbackUtils;
import com.newrelic.agent.security.intcodeagent.apache.httpclient.IastHttpClient;
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

    public static final String CALL_FAILED_REQUEST_S_REASON = "Call failed : request %s reason : %s ";

    public static final String ERROR_IN_FUZZ_REQUEST_GENERATION = "Error in fuzz request generation %s";

    public static final String ERROR_WHILE_PROCESSING_FUZZING_REQUEST_S = "Error while processing fuzzing request : %s";

    public static final String JSON_PARSING_ERROR_WHILE_PROCESSING_FUZZING_REQUEST_S = "JSON parsing error while processing fuzzing request : %s";
    private static final int MAX_REPETITION = 3;
    private static final String IAST_REQUEST_HAS_NO_ARGUMENTS = "IAST request has no arguments : %s";
    public static final String AGENT_IS_NOT_ACTIVE = "Agent is not active";
    public static final String WS_RECONNECTING = "Websocket reconnecting failing for control command id: %s";
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
            logger.log(LogLevel.FINER, String.format(IAST_REQUEST_HAS_NO_ARGUMENTS, controlCommand.getId()), RestRequestProcessor.class.getSimpleName());
            return true;
        }
        if( !AgentInfo.getInstance().isAgentActive()) {
            logger.log(LogLevel.FINER, AGENT_IS_NOT_ACTIVE, RestRequestProcessor.class.getSimpleName());
            return false;
        }

        FuzzRequestBean httpRequest = null;
        try {
            if (WSUtils.getInstance().isReconnecting()) {
                logger.log(LogLevel.FINER, String.format(WS_RECONNECTING, controlCommand.getId()), RestRequestProcessor.class.getSimpleName());
                return false;
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
                    logger.postLogMessageIfNecessary(LogLevel.WARNING,
                            String.format(CALL_FAILED_REQUEST_S_REASON, e.getMessage(), controlCommand.getId()),
                            e, RestRequestProcessor.class.getName());
                    logger.log(LogLevel.FINEST, String.format(ERROR_IN_FUZZ_REQUEST_GENERATION, e.getMessage()), RestRequestProcessor.class.getSimpleName());
                }
                MonitorGrpcFuzzFailRequestQueueThread.submitNewTask();
                GrpcClientRequestReplayHelper.getInstance().addToRequestQueue(new ControlCommandDto(controlCommand.getId(), httpRequest, payloadList));
            } else {
                IastHttpClient.getInstance().replay(NewRelicSecurity.getAgent().getApplicationConnectionConfig(), httpRequest, controlCommand.getId());
            }
            return true;
        } catch (JsonProcessingException e){
            logger.log(LogLevel.SEVERE,
                    String.format(JSON_PARSING_ERROR_WHILE_PROCESSING_FUZZING_REQUEST_S, controlCommand.getArguments().get(0)),
                    e, RestRequestProcessor.class.getName());
            logger.postLogMessageIfNecessary(LogLevel.SEVERE,
                    String.format(JSON_PARSING_ERROR_WHILE_PROCESSING_FUZZING_REQUEST_S, controlCommand.getId()), e, RestRequestProcessor.class.getName());
            RestRequestThreadPool.getInstance().getProcessedIds().putIfAbsent(controlCommand.getId(), new HashSet<>());
        } catch (Throwable e) {
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

    public static void processControlCommand(IntCodeControlCommand command) {
        RestRequestThreadPool.getInstance().executor
                .submit(new RestRequestProcessor(command, MAX_REPETITION));
    }

    public IntCodeControlCommand getControlCommand() {
        return controlCommand;
    }
}
