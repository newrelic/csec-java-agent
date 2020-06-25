package com.k2cybersecurity.intcodeagent.controlcommand;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.k2cybersecurity.instrumentator.K2Instrumentator;
import com.k2cybersecurity.instrumentator.cve.scanner.CVEScannerPool;
import com.k2cybersecurity.instrumentator.httpclient.RestClient;
import com.k2cybersecurity.instrumentator.httpclient.RequestUtils;
import com.k2cybersecurity.instrumentator.utils.AgentUtils;
import com.k2cybersecurity.instrumentator.utils.InstrumentationUtils;
import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import com.k2cybersecurity.intcodeagent.filelogging.LogLevel;
import com.k2cybersecurity.intcodeagent.filelogging.LogWriter;
import com.k2cybersecurity.intcodeagent.logging.IAgentConstants;
import com.k2cybersecurity.intcodeagent.models.javaagent.*;
import com.k2cybersecurity.intcodeagent.websocket.EventSendPool;
import com.k2cybersecurity.intcodeagent.websocket.FtpClient;
import org.apache.commons.lang3.StringUtils;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

import java.io.File;
import java.io.IOException;
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
					&& ProtectionConfig.getInstance().getAutoAddDetectedVulnerabilitiesToProtectionList()) {
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
		case IntCodeControlCommand.PROTECTION_CONFIG:
			try {
				JSONObject jsonObject = (JSONObject) PARSER.parse(controlCommand.getArguments().get(0));
				ProtectionConfig.setInstance((Boolean) jsonObject.get("generateEventResponse"),
						(Boolean) jsonObject.get("protectKnownVulnerableAPIs"),
						(Boolean) jsonObject.get("autoAddDetectedVulnerabilitiesToProtectionList"),
						(Boolean) jsonObject.get("autoAttackIPBlockingXFF"),
						(Boolean) jsonObject.get("protectionMode"));

				if (!ProtectionConfig.getInstance().getProtectionMode()) {
					ProtectionConfig.getInstance().setAutoAddDetectedVulnerabilitiesToProtectionList(false);
					ProtectionConfig.getInstance().setGenerateEventResponse(false);
					ProtectionConfig.getInstance().setProtectKnownVulnerableAPIs(false);
					ProtectionConfig.getInstance().setAutoAttackIPBlockingXFF(false);
				}

				if (!ProtectionConfig.getInstance().getGenerateEventResponse()) {
					ProtectionConfig.getInstance().setProtectKnownVulnerableAPIs(false);
				}
				if (!ProtectionConfig.getInstance().getProtectKnownVulnerableAPIs()) {
					ProtectionConfig.getInstance().setAutoAddDetectedVulnerabilitiesToProtectionList(false);
				}
				logger.log(LogLevel.INFO, "Setting to  : " + ProtectionConfig.getInstance().getGenerateEventResponse(),
						ControlCommandProcessor.class.getSimpleName());
				logger.log(LogLevel.INFO,
						"Setting protection for known vulnerable APIs : "
								+ ProtectionConfig.getInstance().getProtectKnownVulnerableAPIs(),
						ControlCommandProcessor.class.getSimpleName());
				logger.log(LogLevel.INFO,
						"Setting auto add detected vulnerable APIs to protection list : "
								+ ProtectionConfig.getInstance().getAutoAddDetectedVulnerabilitiesToProtectionList(),
						ControlCommandProcessor.class.getSimpleName());
			} catch (Throwable e) {
				logger.log(LogLevel.SEVERE, "Error in ProtectionConfig : ", e,
						ControlCommandProcessor.class.getSimpleName());
				return;
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
			CVEScannerPool.getInstance().dispatchScanner(controlCommand.getArguments().get(0), downloadTarBundle);
			break;
		case IntCodeControlCommand.SET_IPBLOCKING_TIMEOUT:
			if (controlCommand.getArguments().size() != 1) {
				return;
			}
			try {
				long newTimeout = Long.parseLong(controlCommand.getArguments().get(0));
				logger.log(LogLevel.INFO,
						String.format(SETTING_NEW_IP_BLOCKING_TIMEOUT_TO_S_MS, controlCommand.getArguments().get(0)),
						ControlCommandProcessor.class.getName());
				AgentUtils.ipBlockingTimeout = newTimeout;
			} catch (Throwable e) {
				logger.log(LogLevel.ERROR, "Unable to set default IP Blocking timeout due to error:", e,
						ControlCommandProcessor.class.getName());
			}
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
			if (controlCommand.getArguments().size() != 2) {
				return;
			}

			VulnerabilityCaseType currentCaseType = VulnerabilityCaseType.valueOf(controlCommand.getArguments().get(1));
			if(VulnerabilityCaseType.FILE_OPERATION.equals(currentCaseType) ||
					VulnerabilityCaseType.HTTP_REQUEST.equals(currentCaseType)){
				File tempFile = new File("/tmp/k2scanning");
				File tempFileWithExt = new File("/tmp/k2scanning.txt");
				try {
					tempFile.createNewFile();
					tempFileWithExt.createNewFile();
				} catch (IOException e) {
					logger.log(LogLevel.ERROR, String.format("Unable to create setup files for fuzzing request : %s", controlCommand.getArguments().get(0)) , e,
							ControlCommandProcessor.class.getName());
					return;
				}
			}

			HttpRequestBean httpRequest = null;
			try {
				httpRequest = new ObjectMapper()
						.readValue(controlCommand.getArguments().get(0), HttpRequestBean.class);
				RestClient.getInstance().fireRequest(RequestUtils
						.generateK2Request(httpRequest));
			} catch (Exception e) {
				logger.log(LogLevel.ERROR, String.format("Error while processing fuzzing request : %s", controlCommand.getArguments().get(0)) , e,
						ControlCommandProcessor.class.getName());
			}
			break;

		case IntCodeControlCommand.ENABLE_IAST_DYNAMIC_VULNERABILITY_SCANNER:
			logger.log(LogLevel.INFO, String.format("Enabled K2 dynamic scanning mode : %s", controlCommandMessage),
					ControlCommandProcessor.class.getName());
			AgentUtils.getInstance().setEnableDynamicScanning(true);
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
