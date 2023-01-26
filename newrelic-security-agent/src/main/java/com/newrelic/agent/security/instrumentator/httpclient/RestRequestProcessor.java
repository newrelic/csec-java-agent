package com.newrelic.agent.security.instrumentator.httpclient;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.newrelic.agent.security.instrumentator.os.OsVariablesInstance;
import com.newrelic.agent.security.intcodeagent.filelogging.FileLoggerThreadPool;
import com.newrelic.agent.security.intcodeagent.filelogging.LogLevel;
import com.newrelic.agent.security.intcodeagent.models.FuzzRequestBean;
import com.newrelic.agent.security.intcodeagent.models.javaagent.IntCodeControlCommand;
import org.apache.commons.lang3.StringUtils;

/**
 * Request repeater for IAST
 */
public class RestRequestProcessor implements Runnable {

    public static final String K2_HOME_TMP_CONST = "{{K2_HOME_TMP}}";
    public static final String ERROR_WHILE_PROCESSING_FUZZING_REQUEST_S = "Error while processing fuzzing request : %s";
    private IntCodeControlCommand controlCommand;

    private ObjectMapper objectMapper = new ObjectMapper();

    private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

    public RestRequestProcessor(IntCodeControlCommand controlCommand) {
        this.controlCommand = controlCommand;
    }


    /**
     * Does the request replay in IAST mode.
     */
    @Override
    public void run() {
        if (controlCommand.getArguments().size() < 2) {
            return;
        }

        FuzzRequestBean httpRequest = null;
        try {
            String req = StringUtils.replace(controlCommand.getArguments().get(0), K2_HOME_TMP_CONST, OsVariablesInstance.getInstance().getOsVariables().getTmpDirectory());
            httpRequest = objectMapper.readValue(req, FuzzRequestBean.class);
            RestClient.getInstance().fireRequest(RequestUtils.generateK2Request(httpRequest));

        } catch (Throwable e) {
            logger.log(LogLevel.ERROR,
                    String.format(ERROR_WHILE_PROCESSING_FUZZING_REQUEST_S, controlCommand.getArguments().get(0)),
                    e, RestRequestProcessor.class.getName());
            logger.postLogMessageIfNecessary(LogLevel.ERROR,
                    String.format(ERROR_WHILE_PROCESSING_FUZZING_REQUEST_S, controlCommand.getArguments().get(0)),
                    e, RestRequestProcessor.class.getName());
        }
    }

    public static void processControlCommand(IntCodeControlCommand command) {
        RestRequestThreadPool.getInstance().executor
                .submit(new RestRequestProcessor(command));
    }
}
