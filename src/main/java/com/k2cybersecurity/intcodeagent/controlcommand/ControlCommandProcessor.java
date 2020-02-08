package com.k2cybersecurity.intcodeagent.controlcommand;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.k2cybersecurity.instrumentator.K2Instrumentator;
import com.k2cybersecurity.instrumentator.utils.InstrumentationUtils;
import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import com.k2cybersecurity.intcodeagent.filelogging.LogLevel;
import com.k2cybersecurity.intcodeagent.filelogging.LogWriter;
import com.k2cybersecurity.intcodeagent.logging.HealthCheckScheduleThread;
import com.k2cybersecurity.intcodeagent.models.javaagent.EventResponse;
import com.k2cybersecurity.intcodeagent.models.javaagent.IntCodeControlCommand;
import com.k2cybersecurity.intcodeagent.websocket.EventSendPool;
import com.k2cybersecurity.intcodeagent.websocket.FtpClient;
import org.apache.commons.lang3.StringUtils;

import java.util.concurrent.TimeUnit;

public class ControlCommandProcessor implements Runnable {
    public static final String EVENT_RESPONSE_TIME_TAKEN = "Event response time taken : ";
    public static final String DOUBLE_COLON_SEPERATOR = " :: ";

    private String controlCommandMessage;

    private long receiveTimestamp;

    private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

    public ControlCommandProcessor(String controlCommandMessage, long receiveTimestamp) {
        this.controlCommandMessage = controlCommandMessage;
        this.receiveTimestamp = receiveTimestamp;
    }

    @Override
    public void run() {
        if(StringUtils.isBlank(controlCommandMessage)){
            return;
        }
        IntCodeControlCommand controlCommand = null;
        try {
            controlCommand = new ObjectMapper().readValue(controlCommandMessage, IntCodeControlCommand.class);
        } catch (JsonProcessingException e) {
            logger.log(LogLevel.SEVERE, "Error in controlCommandProcessor : ", e, ControlCommandProcessor.class.getSimpleName());
            return;
        }

        switch (controlCommand.getControlCommand()) {
            case IntCodeControlCommand.CHANGE_LOG_LEVEL:
                if (controlCommand.getArguments().size() < 3)
                    break;
                try {
                    LogLevel logLevel = LogLevel.valueOf(controlCommand.getArguments().get(0));
                    Integer duration = Integer.parseInt(controlCommand.getArguments().get(1));
                    TimeUnit timeUnit = TimeUnit.valueOf(controlCommand.getArguments().get(2));
                    LogWriter.updateLogLevel(logLevel, timeUnit, duration);
                } catch (Exception e) {
                    logger.log(LogLevel.SEVERE, "Error in controlCommandProcessor : ", e, ControlCommandProcessor.class.getSimpleName());
                }
                break;

            case IntCodeControlCommand.SHUTDOWN_LANGUAGE_AGENT:
                InstrumentationUtils.shutdownLogic(true);
                break;
            case IntCodeControlCommand.SET_DEFAULT_LOG_LEVEL:
                LogLevel logLevel = LogLevel.valueOf(controlCommand.getArguments().get(0));
                LogWriter.setLogLevel(logLevel);
                break;
            case IntCodeControlCommand.ENABLE_HTTP_REQUEST_PRINTING:
                K2Instrumentator.enableHTTPRequestPrinting = !K2Instrumentator.enableHTTPRequestPrinting;
                break;
            case IntCodeControlCommand.UPLOAD_LOGS:
                logger.log(LogLevel.INFO, "Is log file sent to IC: " + FtpClient.sendBootstrapLogFile(),
                        ControlCommandProcessor.class.getSimpleName());
                break;
            case IntCodeControlCommand.UNSUPPORTED_AGENT:
                logger.log(LogLevel.SEVERE, controlCommand.getArguments().get(0), ControlCommandProcessor.class.getSimpleName());
                System.err.println(controlCommand.getArguments().get(0));
                InstrumentationUtils.shutdownLogic(true);
                break;
            case IntCodeControlCommand.EVENT_RESPONSE:
                EventResponse eventResponse = null;
                try {
                    eventResponse = new ObjectMapper().readValue(controlCommand.getArguments().get(0), EventResponse.class);
                } catch (JsonProcessingException e) {
                    e.printStackTrace();
                }
                long generationTime = EventSendPool.getInstance().getEventMap().get(eventResponse.getId());
                EventSendPool.getInstance().getEventMap().remove(eventResponse.getId());
                if(eventResponse != null) {
                    logger.log(LogLevel.INFO, EVENT_RESPONSE_TIME_TAKEN + eventResponse.getEventId() + DOUBLE_COLON_SEPERATOR + (receiveTimestamp - generationTime), ControlCommandProcessor.class.getSimpleName());
                }
                break;
            case IntCodeControlCommand.SET_WAIT_FOR_VALIDATION_RESPONSE:
                K2Instrumentator.waitForValidationResponse = Boolean.parseBoolean(controlCommand.getArguments().get(0));
                logger.log(LogLevel.INFO, "Setting wait for validation response to  : " + K2Instrumentator.waitForValidationResponse, ControlCommandProcessor.class.getSimpleName());
                break;
            default:
                break;
        }
    }


    public static void processControlCommand(String controlCommandMessage, long receiveTimestamp){
        ControlCommandProcessorThreadPool.getInstance().executor.submit(new ControlCommandProcessor(controlCommandMessage, receiveTimestamp));
    }
}
