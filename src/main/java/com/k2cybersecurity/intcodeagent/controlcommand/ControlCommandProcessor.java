package com.k2cybersecurity.intcodeagent.controlcommand;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.k2cybersecurity.instrumentator.K2Instrumentator;
import com.k2cybersecurity.instrumentator.cve.scanner.CVEScannerPool;
import com.k2cybersecurity.instrumentator.httpclient.RestRequestProcessor;
import com.k2cybersecurity.instrumentator.utils.AgentUtils;
import com.k2cybersecurity.instrumentator.utils.InstrumentationUtils;
import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import com.k2cybersecurity.intcodeagent.filelogging.LogLevel;
import com.k2cybersecurity.intcodeagent.filelogging.LogWriter;
import com.k2cybersecurity.intcodeagent.logging.IAgentConstants;
import com.k2cybersecurity.intcodeagent.models.config.AgentPolicy;
import com.k2cybersecurity.intcodeagent.models.config.AgentPolicyIPBlockingParameters;
import com.k2cybersecurity.intcodeagent.models.javaagent.EventResponse;
import com.k2cybersecurity.intcodeagent.models.javaagent.IntCodeControlCommand;
import com.k2cybersecurity.intcodeagent.websocket.FtpClient;
import org.apache.commons.lang3.StringUtils;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

import java.util.List;
import java.util.concurrent.TimeUnit;

public class ControlCommandProcessor implements Runnable {

	public static final JSONParser PARSER = new JSONParser();
	public static final String EVENT_RESPONSE_ENTRY_NOT_FOUND_FOR_THIS_S = "Event response entry not found for this : %s";
	public static final String EVENT_RESPONSE_TIME_TAKEN = "Event response time taken : ";
	public static final String DOUBLE_COLON_SEPERATOR = " :: ";
	public static final String VULNERABLE_API_ENTRY_CREATED = "vulnerableAPI entry created : ";
	public static final String FAILED_TO_CREATE_VULNERABLE_API_ENTRY = "Failed to create vulnerableAPI entry  : ";
	public static final String EVENT_RESPONSE = "Event response : ";
	public static final String UNKNOWN_CONTROL_COMMAND_S = "Unknown control command : %s";
	public static final String SETTING_NEW_IP_BLOCKING_TIMEOUT_TO_S_MS = "Setting new IP Blocking timeout to %s ms";


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
			break;
		case IntCodeControlCommand.ENABLE_HTTP_REQUEST_PRINTING:
			K2Instrumentator.enableHTTPRequestPrinting = !K2Instrumentator.enableHTTPRequestPrinting;
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
			EventResponse eventResponse = AgentUtils.getInstance().getEventResponseSet()
					.get(controlCommand.getArguments().get(0));
			if (eventResponse == null) {
				logger.log(LogLevel.DEBUG,
						String.format(EVENT_RESPONSE_ENTRY_NOT_FOUND_FOR_THIS_S, controlCommand.getArguments().get(0)),
						ControlCommandProcessor.class.getSimpleName());
				eventResponse = new EventResponse(controlCommand.getArguments().get(0));
			}
			eventResponse.setId(controlCommand.getArguments().get(0));
			eventResponse.setEventId(controlCommand.getArguments().get(1));
			eventResponse.setAttack(Boolean.parseBoolean(controlCommand.getArguments().get(2)));
			eventResponse.setResultMessage(controlCommand.getArguments().get(3));

//			eventResponse.setGenerationTime(Long.parseLong(controlCommand.getArguments().get(4)));
//			eventResponse.setReceivedTime(receiveTimestamp);

//			EventSendPool.getInstance().getEventMap().remove(eventResponse.getId());
			logger.log(LogLevel.DEBUG, EVENT_RESPONSE + eventResponse, ControlCommandProcessor.class.getName());
			if (eventResponse.isAttack()
					&& AgentUtils.getInstance().getAgentPolicy().getProtectionMode().getEnabled()
					&& AgentUtils.getInstance().getAgentPolicy().getProtectionMode().getApiBlocking().getEnabled()
					&& AgentUtils.getInstance().getAgentPolicy().getProtectionMode().getApiBlocking().getProtectAttackedApis()) {
				try {
					VulnerableAPI vulnerableAPI = new VulnerableAPI(controlCommand.getArguments().get(4),
							controlCommand.getArguments().get(5), controlCommand.getArguments().get(6),
							Integer.parseInt(controlCommand.getArguments().get(7)));
					if (!AgentUtils.getInstance().getVulnerableAPIMap().containsKey(vulnerableAPI.getId())) {
						AgentUtils.getInstance().getVulnerableAPIMap().put(vulnerableAPI.getId(), vulnerableAPI);
						logger.log(LogLevel.INFO, VULNERABLE_API_ENTRY_CREATED + vulnerableAPI,
								ControlCommandProcessor.class.getName());
					}
				} catch (Throwable e) {
					logger.log(LogLevel.SEVERE, FAILED_TO_CREATE_VULNERABLE_API_ENTRY + controlCommand, e,
							ControlCommandProcessor.class.getSimpleName());
				}
			}
			eventResponse.getResponseSemaphore().release();
			AgentUtils.getInstance().getEventResponseSet().remove(eventResponse.getId());

//			logger.log(LogLevel.DEBUG,
//					EVENT_RESPONSE_TIME_TAKEN + eventResponse.getEventId() + DOUBLE_COLON_SEPERATOR
//							+ (eventResponse.getReceivedTime() - eventResponse.getGenerationTime()),
//					EventDispatcher.class.getSimpleName());
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
			CVEScannerPool.getInstance().dispatchScanner(controlCommand.getArguments().get(0), downloadTarBundle);
			break;
		case IntCodeControlCommand.CREATE_IPBLOCKING_ENTRY:
			if (controlCommand.getArguments().size() != 1) {
				return;
			}
			String ip = controlCommand.getArguments().get(0);
			logger.log(LogLevel.INFO, String.format("Adding IP address %s to blocking list", ip),
					ControlCommandProcessor.class.getName());
			AgentUtils.getInstance().addIPBlockingEntry(ip);
			break;
			case IntCodeControlCommand.FUZZ_REQUEST:
				RestRequestProcessor.processControlCommand(controlCommand);
				break;

			case IntCodeControlCommand.SEND_POLICY:
				if (controlCommand.getArguments().size() != 1) {
					return;
				}

				try {
					AgentUtils.getInstance().setAgentPolicy(new ObjectMapper().readValue(controlCommand.getArguments().get(0),
							AgentPolicy.class));
					AgentUtils.getInstance().enforcePolicy();
					logger.log(LogLevel.INFO, String.format(IAgentConstants.AGENT_POLICY_APPLIED_S, AgentUtils.getInstance().getAgentPolicy()), ControlCommandProcessor.class.getName());
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
					AgentUtils.getInstance().setAgentPolicyParameters(new ObjectMapper().readValue(controlCommand.getArguments().get(0),
							AgentPolicyIPBlockingParameters.class));
					AgentUtils.getInstance().enforcePolicyParameters();
					logger.log(LogLevel.INFO, String.format(IAgentConstants.AGENT_POLICY_PARAM_APPLIED_S, AgentUtils.getInstance().getAgentPolicyParameters()), ControlCommandProcessor.class.getName());
				} catch (JsonProcessingException e) {
					logger.log(LogLevel.ERROR, IAgentConstants.UNABLE_TO_SET_AGENT_POLICY_PARAM_DUE_TO_ERROR, e,
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
