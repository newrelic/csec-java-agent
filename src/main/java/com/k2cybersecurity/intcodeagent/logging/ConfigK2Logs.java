package com.k2cybersecurity.intcodeagent.logging;

import java.lang.reflect.Method;
import java.util.logging.FileHandler;
import java.util.logging.Formatter;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

import org.brutusin.instrumentation.Agent;

import com.k2cybersecurity.intcodeagent.models.javaagent.AgentBasicInfo;
import com.k2cybersecurity.intcodeagent.models.javaagent.JAHealthCheck;
import com.k2cybersecurity.intcodeagent.properties.K2JALogProperties;
import com.k2cybersecurity.intcodeagent.websocket.WSClient;

public class ConfigK2Logs {

	private Class<?>[] classes = { EIDCount.class, EventThreadPool.class, ExecutionMap.class, IPScheduledThread.class,
			LoggingInterceptor.class, ProcessorThread.class, ServletEventPool.class, ServletEventProcessor.class,
			AgentBasicInfo.class, JAHealthCheck.class, FileWatcher.class, WSClient.class};

	private static ConfigK2Logs loggerInstance;
	public static Level level;
	private int handlerMaxFileSize;
	private String loggerName;
	private int handlerMaxFiles;
	private boolean loggerAdditivity;
	private String fileName = "/etc/k2-adp/logs/k2_java_agent-" + Agent.APPLICATION_UUID + ".log";

	private Object[] emptyObjects = new Object[0];
	private Class<?>[] emptyClasses = new Class<?>[0];

	public ConfigK2Logs() {
		this.handlerMaxFileSize = K2JALogProperties.maxfilesize;
		this.handlerMaxFiles = K2JALogProperties.maxfiles;
		this.loggerName =K2JALogProperties.loggerName;
		this.loggerAdditivity = K2JALogProperties.additivity;

		String loggerMaxSizeUnit = K2JALogProperties.unitMaxfilesize;
		if (loggerMaxSizeUnit.equals("KB")) {
			this.handlerMaxFileSize *= 1024;
		} else if (loggerMaxSizeUnit.equals("MB")) {
			this.handlerMaxFileSize *= 1048576; // 1024 * 1024
		}
		String level = K2JALogProperties.level;
		if (level.equals("OFF")) {
			ConfigK2Logs.level = Level.OFF;
		} else if (level.equals("SEVERE")) {
			ConfigK2Logs.level = Level.SEVERE;
		} else if (level.equals("WARNING")) {
			ConfigK2Logs.level = Level.WARNING;
		} else if (level.equals("INFO")) {
			ConfigK2Logs.level = Level.INFO;
		} else if (level.equals("CONFIG")) {
			ConfigK2Logs.level = Level.CONFIG;
		} else if (level.equals("FINE")) {
			ConfigK2Logs.level = Level.FINE;
		} else if (level.equals("FINER")) {
			ConfigK2Logs.level = Level.FINER;
		} else if (level.equals("FINEST")) {
			ConfigK2Logs.level = Level.FINEST;
		} else if (level.equals("ALL")) {
			ConfigK2Logs.level = Level.ALL;
		}
	}

	public void initializeLogs() {
		try {

			FileHandler handler = new FileHandler(this.fileName, handlerMaxFileSize,
					handlerMaxFiles, true);
			Formatter formatter = new SimpleFormatter();
			handler.setFormatter(formatter);
			Logger logger = Logger.getLogger(loggerName);
			logger.addHandler(handler);
			logger.setLevel(ConfigK2Logs.level);
			logger.setUseParentHandlers(this.loggerAdditivity);

		} catch (Exception e) {
			e.printStackTrace();
		}
		updateAllLocalLoggers();
	}

	public void updateAllLocalLoggers() {
		for (Class<?> clazz : classes) {
			try {
				Method updateLoggerMethod = clazz.getDeclaredMethod("setLogger", this.emptyClasses);
				updateLoggerMethod.invoke(null, this.emptyObjects);
			} catch (Exception e) {
				e.printStackTrace();
			}

		}
	}

	public static ConfigK2Logs getInstance() {
		if (loggerInstance == null) {
			loggerInstance = new ConfigK2Logs();
		}
		return loggerInstance;
	}

	public Level getLevel() {
		return this.level;
	}
}
