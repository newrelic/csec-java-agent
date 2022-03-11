package com.k2cybersecurity.instrumentator.httpclient;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.k2cybersecurity.instrumentator.os.OsVariablesInstance;
import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import com.k2cybersecurity.intcodeagent.filelogging.LogLevel;
import com.k2cybersecurity.intcodeagent.models.javaagent.HttpRequestBean;
import com.k2cybersecurity.intcodeagent.models.javaagent.IntCodeControlCommand;
import org.apache.commons.lang3.StringUtils;

public class RestRequestProcessor implements Runnable {

    public static final String K2_HOME_TMP_CONST = "{{K2_HOME_TMP}}";
    private IntCodeControlCommand controlCommand;

    private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

    public RestRequestProcessor(IntCodeControlCommand controlCommand) {
        this.controlCommand = controlCommand;
    }

    @Override
    public void run() {
        if (controlCommand.getArguments().size() < 2) {
            return;
        }

        HttpRequestBean httpRequest = null;
        try {
            String req = StringUtils.replace(controlCommand.getArguments().get(0), K2_HOME_TMP_CONST, OsVariablesInstance.getInstance().getOsVariables().getTmpDirectory());
            httpRequest = new ObjectMapper().readValue(req, HttpRequestBean.class);
            RestClient.getInstance().fireRequest(RequestUtils.generateK2Request(httpRequest));

        } catch (Throwable e) {
            logger.log(LogLevel.ERROR,
                    String.format("Error while processing fuzzing request : %s", controlCommand.getArguments().get(0)),
                    e, RestRequestProcessor.class.getName());
        }
    }

    public static void processControlCommand(IntCodeControlCommand command) {
        RestRequestThreadPool.getInstance().executor
                .submit(new RestRequestProcessor(command));
    }
}
