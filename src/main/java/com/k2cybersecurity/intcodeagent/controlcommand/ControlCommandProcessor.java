package com.k2cybersecurity.intcodeagent.controlcommand;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.k2cybersecurity.instrumentator.httpclient.RestRequestProcessor;
import com.k2cybersecurity.instrumentator.utils.AgentUtils;
import com.k2cybersecurity.instrumentator.utils.InstrumentationUtils;
import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import com.k2cybersecurity.intcodeagent.filelogging.LogLevel;
import com.k2cybersecurity.intcodeagent.logging.IAgentConstants;
import com.k2cybersecurity.intcodeagent.models.config.AgentPolicy;
import com.k2cybersecurity.intcodeagent.models.javaagent.CollectorInitMsg;
import com.k2cybersecurity.intcodeagent.models.javaagent.EventResponse;
import com.k2cybersecurity.intcodeagent.models.javaagent.IntCodeControlCommand;
import org.apache.commons.lang3.StringUtils;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

import java.util.List;

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
    public static final String FUZZ_REQUEST = "Fuzz request : ";


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
            controlCommand.setData(object.get("data"));
            controlCommand.setControlCommand(Integer.valueOf(object.get("controlCommand").toString()));

        } catch (Throwable e) {
            logger.log(LogLevel.SEVERE, "Error in controlCommandProcessor : ", e,
                    ControlCommandProcessor.class.getSimpleName());
            return;
        }

        switch (controlCommand.getControlCommand()) {

            case IntCodeControlCommand.SHUTDOWN_LANGUAGE_AGENT:
                InstrumentationUtils.shutdownLogic(true);
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
            case IntCodeControlCommand.FUZZ_REQUEST:
                logger.log(LogLevel.DEBUG, FUZZ_REQUEST + controlCommandMessage,
                        ControlCommandProcessor.class.getName());
                RestRequestProcessor.processControlCommand(controlCommand);
                break;

            case IntCodeControlCommand.SEND_POLICY:
                if (controlCommand.getData() == null) {
                    logger.log(LogLevel.WARNING, controlCommand.toString(), ControlCommandProcessor.class.getName());
                    return;
                }

                try {
                    AgentPolicy newPolicy = new ObjectMapper().readValue(controlCommand.getData().toString(), AgentPolicy.class);
                    if (StringUtils.equals(newPolicy.getVersion(), AgentUtils.getInstance().getAgentPolicy().getVersion())) {
                        return;
                    }
                    AgentUtils.getInstance().setAgentPolicy(newPolicy);
                    AgentUtils.getInstance().enforcePolicy();
                    logger.log(LogLevel.INFO, String.format(IAgentConstants.AGENT_POLICY_APPLIED_S,
                            AgentUtils.getInstance().getAgentPolicy()), ControlCommandProcessor.class.getName());
                } catch (Throwable e) {
                    logger.log(LogLevel.ERROR, IAgentConstants.UNABLE_TO_SET_AGENT_POLICY_DUE_TO_ERROR, e,
                            ControlCommandProcessor.class.getName());
                }

                break;

            case IntCodeControlCommand.STARTUP_WELCOME_MSG:
                if (controlCommand.getData() == null) {
                    return;
                }

                try {
                    AgentUtils.getInstance().setInitMsg(
                            new ObjectMapper().readValue(controlCommand.getData().toString(), CollectorInitMsg.class));
                    logger.log(LogLevel.INFO,
                            String.format(COLLECTOR_IS_INITIALIZED_WITH_PROPERTIES, AgentUtils.getInstance().getInitMsg().toString()),
                            ControlCommandProcessor.class.getName());
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
