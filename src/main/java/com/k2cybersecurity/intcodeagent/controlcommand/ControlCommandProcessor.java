package com.k2cybersecurity.intcodeagent.controlcommand;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.k2cybersecurity.instrumentator.K2Instrumentator;
import com.k2cybersecurity.instrumentator.cve.scanner.CVEScannerPool;
import com.k2cybersecurity.instrumentator.httpclient.RestRequestProcessor;
import com.k2cybersecurity.instrumentator.utils.AgentUtils;
import com.k2cybersecurity.instrumentator.utils.CommonUtils;
import com.k2cybersecurity.instrumentator.utils.InstrumentationUtils;
import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import com.k2cybersecurity.intcodeagent.filelogging.LogLevel;
import com.k2cybersecurity.intcodeagent.filelogging.LogWriter;
import com.k2cybersecurity.intcodeagent.logging.IAgentConstants;
import com.k2cybersecurity.intcodeagent.models.config.AgentPolicy;
import com.k2cybersecurity.intcodeagent.models.config.AgentPolicyIPBlockingParameters;
import com.k2cybersecurity.intcodeagent.models.javaagent.CollectorInitMsg;
import com.k2cybersecurity.intcodeagent.models.javaagent.EventResponse;
import com.k2cybersecurity.intcodeagent.models.javaagent.Identifier;
import com.k2cybersecurity.intcodeagent.models.javaagent.IntCodeControlCommand;
import com.k2cybersecurity.intcodeagent.websocket.FtpClient;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.Pair;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

import java.util.List;
import java.util.concurrent.TimeUnit;

public class ControlCommandProcessor implements Runnable {

    private static final String COLLECTOR_IS_INITIALIZED_WITH_PROPERTIES = "Collector is initialized with properties : %s";
    public static final JSONParser PARSER = new JSONParser();
    public static final String EVENT_RESPONSE_ENTRY_NOT_FOUND_FOR_THIS_S = "Event response entry not found for this : %s";
    public static final String EVENT_RESPONSE_TIME_TAKEN = "Event response time taken : ";
    public static final String DOUBLE_COLON_SEPERATOR = " :: ";
    public static final String FAILED_TO_CREATE_VULNERABLE_API_ENTRY = "Failed to create vulnerableAPI entry  : ";
    public static final String EVENT_RESPONSE = "Event response : ";
    public static final String UNKNOWN_CONTROL_COMMAND_S = "Unknown control command : %s";
    public static final String SETTING_NEW_IP_BLOCKING_TIMEOUT_TO_S_MS = "Setting new IP Blocking timeout to %s ms";
    public static final String ATTACKED_API_BLOCKED_S = "Attacked API added to blocked list : %s";
    public static final String ADDING_IP_ADDRESS_S_TO_BLOCKING_LIST_WITH_TIMEOUT_S = "Adding IP address %s to blocking list with timeout %s";
    public static final String ERROR_IN_EVENT_RESPONSE = "Error in EVENT_RESPONSE : ";


    private String controlCommandMessage;

    private long receiveTimestamp;

    private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

    public ControlCommandProcessor(String controlCommandMessage, long receiveTimestamp) {
        this.controlCommandMessage = controlCommandMessage;
        this.receiveTimestamp = receiveTimestamp;
    }

    @Override
    public void run() {
        if (StringUtils.isBlank(controlCommandMessage)) {
            return;
        }
        IntCodeControlCommand controlCommand = null;
        try {
            JSONObject object = (JSONObject) PARSER.parse(controlCommandMessage);
            controlCommand = new IntCodeControlCommand();
            controlCommand.setArguments((List<String>) object.get("arguments"));
            controlCommand.setControlCommand(Integer.valueOf(object.get("controlCommand").toString()));

        } catch (Throwable e) {
            logger.log(LogLevel.SEVERE, "Error in controlCommandProcessor : ", e,
                    ControlCommandProcessor.class.getSimpleName());
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
                } catch (Throwable e) {
                    logger.log(LogLevel.SEVERE, "Error in controlCommandProcessor : ", e,
                            ControlCommandProcessor.class.getSimpleName());
                }
                break;

            case IntCodeControlCommand.SHUTDOWN_LANGUAGE_AGENT:
                InstrumentationUtils.shutdownLogic(true);
                break;
            case IntCodeControlCommand.SET_DEFAULT_LOG_LEVEL:
                LogLevel logLevel = LogLevel.valueOf(controlCommand.getArguments().get(0));
                LogWriter.setLogLevel(logLevel);
                logger.log(LogLevel.INFO, "Changed default log level to " + controlCommand.getArguments().get(0),
                        ControlCommandProcessor.class.getSimpleName());
                break;
            case IntCodeControlCommand.UPLOAD_LOGS:
                logger.log(LogLevel.INFO, "Is log file sent to IC: " + FtpClient.sendBootstrapLogFile(),
                        ControlCommandProcessor.class.getSimpleName());
                break;
            case IntCodeControlCommand.UNSUPPORTED_AGENT:
                logger.log(LogLevel.SEVERE, controlCommand.getArguments().get(0),
                        ControlCommandProcessor.class.getSimpleName());
                System.err.println(controlCommand.getArguments().get(0));
                InstrumentationUtils.shutdownLogic(true);
                break;
            case IntCodeControlCommand.EVENT_RESPONSE:
                boolean cleanUp = false;
                try {
                    EventResponse receivedEventResponse = new ObjectMapper().readValue(controlCommand.getArguments().get(0),
                            EventResponse.class);

                    EventResponse eventResponse = AgentUtils.getInstance().getEventResponseSet()
                            .get(receivedEventResponse.getId());
                    if (eventResponse == null) {
                        logger.log(LogLevel.DEBUG,
                                String.format(EVENT_RESPONSE_ENTRY_NOT_FOUND_FOR_THIS_S, receivedEventResponse),
                                ControlCommandProcessor.class.getSimpleName());
                        cleanUp = true;
                    } else {
                        receivedEventResponse.setResponseSemaphore(eventResponse.getResponseSemaphore());
                    }

                    AgentUtils.getInstance().getEventResponseSet().put(receivedEventResponse.getId(),
                            receivedEventResponse);

                    logger.log(LogLevel.DEBUG, EVENT_RESPONSE + receivedEventResponse,
                            ControlCommandProcessor.class.getName());

                    receivedEventResponse.getResponseSemaphore().release();
                    if (cleanUp) {
                        AgentUtils.getInstance().getEventResponseSet().remove(receivedEventResponse.getId());
                    }
                } catch (Exception e) {
                    logger.log(LogLevel.SEVERE, ERROR_IN_EVENT_RESPONSE, e, ControlCommandProcessor.class.getSimpleName());
                }
                break;
            case IntCodeControlCommand.START_VULNERABILITY_SCAN:
                boolean fullReScanning = false;
                boolean downloadTarBundle = false;

                if (controlCommand.getArguments().size() == 3) {
                    fullReScanning = Boolean.parseBoolean(controlCommand.getArguments().get(1));
                    downloadTarBundle = Boolean.parseBoolean(controlCommand.getArguments().get(2));
                }
                logger.log(LogLevel.INFO, String.format(
                        "Starting K2 Vulnerability scanner on this instance : %s :: Full Rescan : %s :: Download tar bundle : %s",
                        controlCommand.getArguments().get(0), fullReScanning, downloadTarBundle),
                        ControlCommandProcessor.class.getSimpleName());
                // This essentially mean to clear the scanned application entries.
                if (fullReScanning) {
                    AgentUtils.getInstance().getScannedDeployedApplications().clear();
                }
                Pair<String, String> kindId = CommonUtils.getKindIdPair(K2Instrumentator.APPLICATION_INFO_BEAN.getIdentifier(), controlCommand.getArguments().get(0));
                CVEScannerPool.getInstance().dispatchScanner(controlCommand.getArguments().get(0), kindId.getKey(), kindId.getValue(), downloadTarBundle, false);
                break;
            case IntCodeControlCommand.FUZZ_REQUEST:
                RestRequestProcessor.processControlCommand(controlCommand);
                break;

            case IntCodeControlCommand.SEND_POLICY:
                if (controlCommand.getArguments().size() != 1) {
                    return;
                }

                try {
                    AgentUtils.getInstance().setAgentPolicy(
                            new ObjectMapper().readValue(controlCommand.getArguments().get(0), AgentPolicy.class));
                    AgentUtils.getInstance().enforcePolicy();
                    logger.log(LogLevel.INFO, String.format(IAgentConstants.AGENT_POLICY_APPLIED_S,
                            AgentUtils.getInstance().getAgentPolicy()), ControlCommandProcessor.class.getName());
                } catch (JsonProcessingException e) {
                    logger.log(LogLevel.ERROR, IAgentConstants.UNABLE_TO_SET_AGENT_POLICY_DUE_TO_ERROR, e,
                            ControlCommandProcessor.class.getName());
                }

                break;

            case IntCodeControlCommand.SEND_POLICY_PARAM:
                if (controlCommand.getArguments().size() != 1) {
                    return;
                }

                try {
                    AgentUtils.getInstance().setAgentPolicyParameters(new ObjectMapper()
                            .readValue(controlCommand.getArguments().get(0), AgentPolicyIPBlockingParameters.class));
                    AgentUtils.getInstance().enforcePolicyParameters();
                    logger.log(LogLevel.INFO,
                            String.format(IAgentConstants.AGENT_POLICY_PARAM_APPLIED_S,
                                    AgentUtils.getInstance().getAgentPolicyParameters()),
                            ControlCommandProcessor.class.getName());
                } catch (JsonProcessingException e) {
                    logger.log(LogLevel.ERROR, IAgentConstants.UNABLE_TO_SET_AGENT_POLICY_PARAM_DUE_TO_ERROR, e,
                            ControlCommandProcessor.class.getName());
                }

                break;
            case IntCodeControlCommand.STARTUP_WELCOME_MSG:
                if (controlCommand.getArguments().size() != 1) {
                    return;
                }

                try {
                    CollectorInitMsg initMsg = new ObjectMapper().readValue(controlCommand.getArguments().get(0),
                            CollectorInitMsg.class);
                    AgentUtils.getInstance().setInitMsg(initMsg);
                    logger.log(LogLevel.INFO,
                            String.format(COLLECTOR_IS_INITIALIZED_WITH_PROPERTIES, initMsg.toString()),
                            ControlCommandProcessor.class.getName());
                    logLevel = LogLevel.valueOf(initMsg.getStartupProperties().getLogLevel());
                    LogWriter.setLogLevel(logLevel);
                    K2Instrumentator.enableHTTPRequestPrinting = initMsg.getStartupProperties().isPrintHttpRequest();
                } catch (JsonProcessingException e) {
                    logger.log(LogLevel.ERROR, IAgentConstants.UNABLE_TO_GET_AGENT_STARTUP_INFOARMATION, e,
                            ControlCommandProcessor.class.getName());
                }

                break;

            default:
                logger.log(LogLevel.WARNING, String.format(UNKNOWN_CONTROL_COMMAND_S, controlCommandMessage),
                        ControlCommandProcessor.class.getName());
                break;
        }
    }

    public static void processControlCommand(String controlCommandMessage, long receiveTimestamp) {
        ControlCommandProcessorThreadPool.getInstance().executor
                .submit(new ControlCommandProcessor(controlCommandMessage, receiveTimestamp));
    }
}
