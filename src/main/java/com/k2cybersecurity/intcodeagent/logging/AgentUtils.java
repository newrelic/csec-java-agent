package com.k2cybersecurity.intcodeagent.logging;

import com.k2cybersecurity.instrumentator.K2Instrumentator;
import com.k2cybersecurity.instrumentator.utils.InstrumentationUtils;
import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import com.k2cybersecurity.intcodeagent.filelogging.LogLevel;
import com.k2cybersecurity.intcodeagent.filelogging.LogWriter;
import com.k2cybersecurity.intcodeagent.models.javaagent.IntCodeControlCommand;
import com.k2cybersecurity.intcodeagent.websocket.FtpClient;

import java.util.concurrent.TimeUnit;

import org.apache.commons.net.ftp.FTPClient;

public class AgentUtils {

	private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

	public static void controlCommandProcessor(IntCodeControlCommand controlCommand) {
		switch (controlCommand.getControlCommand()) {
		case IntCodeControlCommand.CHANGE_LOG_LEVEL:
			if (controlCommand.getArguements().size() < 3)
				break;
			try {
				LogLevel logLevel = LogLevel.valueOf(controlCommand.getArguements().get(0));
				Integer duration = Integer.parseInt(controlCommand.getArguements().get(1));
				TimeUnit timeUnit = TimeUnit.valueOf(controlCommand.getArguements().get(2));
				LogWriter.updateLogLevel(logLevel, timeUnit, duration);
			} catch (Exception e) {
				logger.log(LogLevel.SEVERE, "Error in controlCommandProcessor : ", e, AgentUtils.class.getSimpleName());
			}
			break;

		case IntCodeControlCommand.SHUTDOWN_LANGUAGE_AGENT:
			InstrumentationUtils.shutdownLogic();
			break;
		case IntCodeControlCommand.SET_DEFAULT_LOG_LEVEL:
			LogLevel logLevel = LogLevel.valueOf(controlCommand.getArguements().get(0));
			LogWriter.setLogLevel(logLevel);
			break;
		case IntCodeControlCommand.ENABLE_HTTP_REQUEST_PRINTING:
			K2Instrumentator.enableHTTPRequestPrinting = !K2Instrumentator.enableHTTPRequestPrinting;
			break;
		case IntCodeControlCommand.UPLOAD_LOGS:
			logger.log(LogLevel.INFO, "Is log file sent to IC: " + FtpClient.sendBootstrapLogFile(),
					AgentUtils.class.getSimpleName());
			break;
		default:
			break;
		}
	}
}
