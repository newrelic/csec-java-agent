package com.k2cybersecurity.instrumentator.httpclient;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.k2cybersecurity.instrumentator.os.OsVariablesInstance;
import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import com.k2cybersecurity.intcodeagent.filelogging.LogLevel;
import com.k2cybersecurity.intcodeagent.models.javaagent.HttpRequestBean;
import com.k2cybersecurity.intcodeagent.models.javaagent.IntCodeControlCommand;
import com.k2cybersecurity.intcodeagent.models.javaagent.VulnerabilityCaseType;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

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

        List<String> filesCreated = new ArrayList<>();

        VulnerabilityCaseType currentCaseType = VulnerabilityCaseType.valueOf(controlCommand.getArguments().get(1));
        if (VulnerabilityCaseType.FILE_OPERATION.equals(currentCaseType)
                || VulnerabilityCaseType.HTTP_REQUEST.equals(currentCaseType)) {

            if (controlCommand.getArguments().size() >= 2) {
                for (int i = 2; i < controlCommand.getArguments().size(); i++) {
                    String file = controlCommand.getArguments().get(i);
                    file = StringUtils.replace(file, K2_HOME_TMP_CONST, OsVariablesInstance.getInstance().getOsVariables().getTmpDirectory());
                    File fileToCreate = new File(file);
                    try {
                        if (fileToCreate.getParentFile() != null) {
                            fileToCreate.getParentFile().mkdirs();
                        }
                        FileUtils.touch(fileToCreate);
                    } catch (Exception e) {
                        logger.log(LogLevel.ERROR, String.format("Unable to create setup files for fuzzing request : %s : %s : %s",
                                fileToCreate, e.getMessage(), e.getCause()), RestRequestProcessor.class.getName());
                    } finally {
                        filesCreated.add(file);
                    }
                }
            }

        }

        HttpRequestBean httpRequest = null;
        try {
            String req = StringUtils.replace(controlCommand.getArguments().get(0), K2_HOME_TMP_CONST, OsVariablesInstance.getInstance().getOsVariables().getTmpDirectory());
            httpRequest = new ObjectMapper().readValue(req, HttpRequestBean.class);
            RestClient.getInstance().fireRequest(RequestUtils.generateK2Request(httpRequest));
            // TODO: Create one schedule for this.
            filesCreated.forEach((path) -> {
                FuzzCleanUpST.getInstance().scheduleCleanUp(path);
            });
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
