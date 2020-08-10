package com.k2cybersecurity.instrumentator.httpclient;

import java.io.File;
import java.io.IOException;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import com.k2cybersecurity.intcodeagent.filelogging.LogLevel;
import com.k2cybersecurity.intcodeagent.models.javaagent.HttpRequestBean;
import com.k2cybersecurity.intcodeagent.models.javaagent.IntCodeControlCommand;
import com.k2cybersecurity.intcodeagent.models.javaagent.VulnerabilityCaseType;

import java.io.File;
import java.io.IOException;

public class RestRequestProcessor implements Runnable {

    private static final String TMP_K2SCANNING_TXT = "/tmp/k2scanning.txt";

    private static final String TMP_K2SCANNING = "/tmp/k2scanning";

    private IntCodeControlCommand controlCommand;

    private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

    public RestRequestProcessor(IntCodeControlCommand controlCommand) {
        this.controlCommand = controlCommand;
    }

    @Override
    public void run() {

        if (controlCommand.getArguments().size() != 2) {
            return;
        }

        VulnerabilityCaseType currentCaseType = VulnerabilityCaseType.valueOf(controlCommand.getArguments().get(1));
        if (VulnerabilityCaseType.FILE_OPERATION.equals(currentCaseType)
                || VulnerabilityCaseType.HTTP_REQUEST.equals(currentCaseType)) {
            File tempFile = new File(TMP_K2SCANNING);
            File tempFileWithExt = new File(TMP_K2SCANNING_TXT);
            try {
                tempFile.createNewFile();
                tempFileWithExt.createNewFile();
            } catch (IOException e) {
                logger.log(LogLevel.ERROR, String.format("Unable to create setup files for fuzzing request : %s",
                        controlCommand.getArguments().get(0)), e, RestRequestProcessor.class.getName());
                return;
            }
        }

        HttpRequestBean httpRequest = null;
        try {
            httpRequest = new ObjectMapper().readValue(controlCommand.getArguments().get(0), HttpRequestBean.class);
            RestClient.getInstance().fireRequest(RequestUtils.generateK2Request(httpRequest));
        } catch (Exception e) {
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
