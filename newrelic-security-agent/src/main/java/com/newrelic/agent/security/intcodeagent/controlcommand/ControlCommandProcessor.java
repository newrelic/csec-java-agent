package com.newrelic.agent.security.intcodeagent.controlcommand;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.newrelic.agent.security.instrumentator.httpclient.RestRequestProcessor;
import com.newrelic.agent.security.instrumentator.httpclient.RestRequestThreadPool;
import com.newrelic.agent.security.instrumentator.utils.AgentUtils;
import com.newrelic.agent.security.instrumentator.utils.InstrumentationUtils;
import com.newrelic.agent.security.intcodeagent.filelogging.FileLoggerThreadPool;
import com.newrelic.agent.security.intcodeagent.filelogging.LogLevel;
import com.newrelic.agent.security.intcodeagent.logging.IAgentConstants;
import com.newrelic.agent.security.intcodeagent.models.config.AgentPolicyParameters;
import com.newrelic.agent.security.intcodeagent.models.javaagent.CollectorInitMsg;
import com.newrelic.agent.security.intcodeagent.models.javaagent.EventResponse;
import com.newrelic.agent.security.intcodeagent.models.javaagent.IntCodeControlCommand;
import com.newrelic.agent.security.intcodeagent.utils.CommonUtils;
import com.newrelic.agent.security.intcodeagent.websocket.EventSendPool;
import com.newrelic.agent.security.intcodeagent.websocket.JsonConverter;
import com.newrelic.agent.security.intcodeagent.websocket.WSClient;
import com.newrelic.agent.security.intcodeagent.websocket.WSUtils;
import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.schema.policy.AgentPolicy;
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
    public static final String POLICY_PARAMETERS_ARE_UPDATED_TO_S = "Policy parameters are updated to : %s";
    public static final String UPDATED_POLICY_FAILED_VALIDATION_REVERTING_TO_DEFAULT_POLICY_FOR_THE_MODE = "Updated policy failed validation. Reverting to default policy for the mode";
    public static final String ERROR_WHILE_PROCESSING_RECONNECTION_CC_S_S = "Error while processing reconnection CC : %s : %s";
    public static final String ERROR_WHILE_PROCESSING_RECONNECTION_CC = "Error while processing reconnection CC :";
    public static final String UNABLE_TO_PARSE_RECEIVED_DEFAULT_POLICY = "Unable to parse received default policy : ";
    public static final String ERROR_IN_CONTROL_COMMAND_PROCESSOR = "Error in controlCommandProcessor : ";
    public static final String ARGUMENTS = "arguments";
    public static final String DATA = "data";
    public static final String CONTROL_COMMAND = "controlCommand";
    public static final String RECEIVED_WS_RECONNECT_COMMAND_FROM_SERVER_INITIATING_SEQUENCE = "Received WS 'reconnect' command from server. Initiating sequence.";
    public static final String WS_RECONNECT_EVENT_SEND_POOL_DRAINED = "[WS RECONNECT] EventSend pool drained.";
    public static final String WS_RECONNECT_IAST_REQUEST_REPLAY_POOL_DRAINED = "[WS RECONNECT] IAST request replay pool drained.";


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
            controlCommand.setArguments((List<String>) object.get(ARGUMENTS));
            controlCommand.setData(object.get(DATA));
            controlCommand.setControlCommand(Integer.valueOf(object.get(CONTROL_COMMAND).toString()));

        } catch (Throwable e) {
            logger.log(LogLevel.FATAL, ERROR_IN_CONTROL_COMMAND_PROCESSOR, e,
                    ControlCommandProcessor.class.getSimpleName());
            return;
        }

        switch (controlCommand.getControlCommand()) {

            case IntCodeControlCommand.SHUTDOWN_LANGUAGE_AGENT:
                InstrumentationUtils.shutdownLogic(true);
                break;
            case IntCodeControlCommand.UNSUPPORTED_AGENT:
                logger.log(LogLevel.FATAL, controlCommand.getArguments().get(0),
                        ControlCommandProcessor.class.getSimpleName());
                System.err.println(controlCommand.getArguments().get(0));
                InstrumentationUtils.shutdownLogic(true);
                break;

            case IntCodeControlCommand.SEND_POLICY_PARAMETERS:
                if (controlCommand.getData() == null) {
                    return;
                }
                try {
                    AgentPolicyParameters parameters = JsonConverter.getObjectMapper()
                            .readValue(controlCommand.getData().toString(), AgentPolicyParameters.class);
                    if (!CommonUtils.validateCollectorPolicyParameterSchema(parameters)) {
                        logger.log(LogLevel.WARN, String.format(IAgentConstants.UNABLE_TO_VALIDATE_AGENT_POLICY_PARAMETER_DUE_TO_ERROR, parameters), ControlCommandProcessor.class.getName());
                        return;
                    }
                    AgentUtils.getInstance().setAgentPolicyParameters(parameters);
                    logger.logInit(LogLevel.INFO,
                            String.format(IAgentConstants.AGENT_POLICY_PARAM_APPLIED_S, AgentUtils.getInstance().getAgentPolicyParameters()),
                            ControlCommandProcessor.class.getName());
                } catch (JsonProcessingException e) {
                    logger.logInit(LogLevel.DEBUG, IAgentConstants.UNABLE_TO_SET_AGENT_POLICY_PARAM_DUE_TO_ERROR, e,
                            ControlCommandProcessor.class.getName());
                }
                break;

            case IntCodeControlCommand.EVENT_RESPONSE:
                boolean cleanUp = false;
                try {
                    EventResponse receivedEventResponse = JsonConverter.getObjectMapper().readValue(controlCommand.getArguments().get(0),
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
                    logger.log(LogLevel.FATAL, ERROR_IN_EVENT_RESPONSE, e, ControlCommandProcessor.class.getSimpleName());
                }
                break;
            case IntCodeControlCommand.FUZZ_REQUEST:
                logger.log(LogLevel.DEBUG, FUZZ_REQUEST + controlCommandMessage,
                        ControlCommandProcessor.class.getName());
                RestRequestProcessor.processControlCommand(controlCommand);
                break;

            case IntCodeControlCommand.STARTUP_WELCOME_MSG:
                if (controlCommand.getData() == null) {
                    return;
                }

                try {
                    AgentUtils.getInstance().setInitMsg(
                            JsonConverter.getObjectMapper().readValue(controlCommand.getData().toString(), CollectorInitMsg.class));
                    // TODO : Remove usage of CC #10 data
                    logger.log(LogLevel.INFO,
                            String.format(COLLECTOR_IS_INITIALIZED_WITH_PROPERTIES, AgentUtils.getInstance().getInitMsg().toString()),
                            ControlCommandProcessor.class.getName());
                } catch (JsonProcessingException e) {
                    logger.log(LogLevel.ERROR, IAgentConstants.UNABLE_TO_GET_AGENT_STARTUP_INFOARMATION, e,
                            ControlCommandProcessor.class.getName());
                }

                break;

            case IntCodeControlCommand.SEND_POLICY:
                if (controlCommand.getData() == null) {
                    return;
                }
                try {
                    AgentPolicy policy = JsonConverter.getObjectMapper().convertValue(controlCommand.getData(), AgentPolicy.class);
                    logger.logInit(LogLevel.INFO,
                            String.format(IAgentConstants.RECEIVED_AGENT_POLICY, JsonConverter.toJSON(policy)),
                            AgentUtils.class.getName());
                    AgentUtils.getInstance().setDefaultAgentPolicy(policy);
                    if (AgentUtils.applyPolicy(policy)) {
                        AgentUtils.getInstance().applyPolicyOverrideIfApplicable();
                    }
                } catch (IllegalArgumentException e) {
                    logger.log(LogLevel.ERROR, UNABLE_TO_PARSE_RECEIVED_DEFAULT_POLICY, e,
                            ControlCommandProcessor.class.getName());
                }
                break;
            case IntCodeControlCommand.POLICY_UPDATE_FAILED_DUE_TO_VALIDATION_ERROR:
                logger.log(LogLevel.WARN, UPDATED_POLICY_FAILED_VALIDATION_REVERTING_TO_DEFAULT_POLICY_FOR_THE_MODE,
                        ControlCommandProcessor.class.getName());
                AgentUtils.instantiateDefaultPolicy();
                break;
            case IntCodeControlCommand.RECONNECT_AT_WILL:
                /* This is only when we have IastScan enabled
                 * 1. Mark LC in reconnecting phase
                 * 2. Let IAST request processor ideal out.
                 * 3. Mark LC in inactive state by disconnecting WS connection.
                 * 4. Initiate WS reconnect
                 *
                 * Post reconnect: reset 'reconnecting phase' in WSClient.
                 */
                try {
                    logger.log(LogLevel.INFO, RECEIVED_WS_RECONNECT_COMMAND_FROM_SERVER_INITIATING_SEQUENCE, this.getClass().getName());
                    if (NewRelicSecurity.getAgent().getCurrentPolicy().getVulnerabilityScan().getEnabled() &&
                            NewRelicSecurity.getAgent().getCurrentPolicy().getVulnerabilityScan().getIastScan().getEnabled()
                    ) {
                        WSUtils.getInstance().setReconnecting(true);
                        while (EventSendPool.getInstance().getExecutor().getActiveCount() > 0 && !EventSendPool.getInstance().isWaiting().get()) {
                            Thread.sleep(100);
                        }
                        logger.log(LogLevel.DEBUG, WS_RECONNECT_EVENT_SEND_POOL_DRAINED, this.getClass().getName());

                        while (RestRequestThreadPool.getInstance().getExecutor().getActiveCount() > 0 && !RestRequestThreadPool.getInstance().isWaiting().get()) {
                            Thread.sleep(100);
                        }
                        logger.log(LogLevel.DEBUG, WS_RECONNECT_IAST_REQUEST_REPLAY_POOL_DRAINED, this.getClass().getName());
                    }
                    WSClient.reconnectWSClient();
                } catch (Throwable e) {
                    logger.log(LogLevel.ERROR, String.format(ERROR_WHILE_PROCESSING_RECONNECTION_CC_S_S, e.getMessage(), e.getCause()), this.getClass().getName());
                    logger.log(LogLevel.ERROR, ERROR_WHILE_PROCESSING_RECONNECTION_CC, e, this.getClass().getName());
                }
                break;
            default:
                logger.log(LogLevel.WARN, String.format(UNKNOWN_CONTROL_COMMAND_S, controlCommandMessage),
                        ControlCommandProcessor.class.getName());
                break;
        }
    }

    public static void processControlCommand(String controlCommandMessage, long receiveTimestamp) {
        ControlCommandProcessorThreadPool.getInstance().executor
                .submit(new ControlCommandProcessor(controlCommandMessage, receiveTimestamp));
    }
}
