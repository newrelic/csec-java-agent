package com.newrelic.agent.security.instrumentator.httpclient;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.newrelic.agent.security.AgentInfo;
import com.newrelic.agent.security.instrumentator.os.OsVariablesInstance;
import com.newrelic.agent.security.intcodeagent.filelogging.FileLoggerThreadPool;
import com.newrelic.agent.security.intcodeagent.filelogging.LogLevel;
import com.newrelic.agent.security.intcodeagent.models.FuzzRequestBean;
import com.newrelic.agent.security.intcodeagent.models.javaagent.IntCodeControlCommand;
import com.newrelic.agent.security.intcodeagent.websocket.WSUtils;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import okhttp3.Request;
import org.apache.commons.lang3.StringUtils;

import java.util.concurrent.Callable;

/**
 * Request repeater for IAST
 */
public class RestRequestProcessor implements Callable<Boolean> {

    public static final String NR_CSEC_VALIDATOR_HOME_TMP = "{{NR_CSEC_VALIDATOR_HOME_TMP}}";

    public static final String ERROR_WHILE_PROCESSING_FUZZING_REQUEST_S = "Error while processing fuzzing request : %s";

    public static final String JSON_PARSING_ERROR_WHILE_PROCESSING_FUZZING_REQUEST_S = "JSON parsing error while processing fuzzing request : %s";
    private static final int MAX_REPETITION = 3;
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

        FuzzRequestBean httpRequest;
        try {
            if (WSUtils.getInstance().isReconnecting()) {
                   synchronized (WSUtils.getInstance()) {
                    RestRequestThreadPool.getInstance().isWaiting().set(true);
                    WSUtils.getInstance().wait();
                    RestRequestThreadPool.getInstance().isWaiting().set(false);
                }
            }
            String req = StringUtils.replace(controlCommand.getArguments().get(0), NR_CSEC_VALIDATOR_HOME_TMP, OsVariablesInstance.getInstance().getOsVariables().getTmpDirectory());
            httpRequest = objectMapper.readValue(req, FuzzRequestBean.class);
            httpRequest.getHeaders().put(GenericHelper.CSEC_PARENT_ID, controlCommand.getId());
            RestRequestThreadPool.getInstance().removeFromProcessedCC(controlCommand.getId());
            Request request = RequestUtils.generateK2Request(httpRequest);
            if(request != null) {
                RestClient.getInstance().fireRequest(request, repeatCount, controlCommand.getId());
            }
            return true;
        } catch (JsonProcessingException e){
            logger.log(LogLevel.SEVERE,
                    String.format(JSON_PARSING_ERROR_WHILE_PROCESSING_FUZZING_REQUEST_S, controlCommand.getArguments().get(0)),
                    e, RestRequestProcessor.class.getName());
            logger.postLogMessageIfNecessary(LogLevel.SEVERE,
                    String.format(JSON_PARSING_ERROR_WHILE_PROCESSING_FUZZING_REQUEST_S, controlCommand.getId()), e, RestRequestProcessor.class.getName());
        } catch (Throwable e) {
            logger.log(LogLevel.SEVERE,
                    String.format(ERROR_WHILE_PROCESSING_FUZZING_REQUEST_S, controlCommand.getArguments().get(0)),
                    e, RestRequestProcessor.class.getName());
            logger.postLogMessageIfNecessary(LogLevel.SEVERE,
                    String.format(ERROR_WHILE_PROCESSING_FUZZING_REQUEST_S, controlCommand.getId()),
                    e, RestRequestProcessor.class.getName());
            throw e;
        }
        return true;
    }

    public static void processControlCommand(IntCodeControlCommand command) {
        RestRequestThreadPool.getInstance().executor
                .submit(new RestRequestProcessor(command, MAX_REPETITION));
        RestRequestThreadPool.getInstance().getPendingIds().add(command.getId());
    }

    public IntCodeControlCommand getControlCommand() {
        return controlCommand;
    }
}
