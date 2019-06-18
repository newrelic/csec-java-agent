package com.k2cybersecurity.intcodeagent.logging;

import java.io.IOException;
import java.lang.reflect.Method;
import java.util.Map;
import java.util.Properties;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.Logger;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.appender.RollingFileAppender;
import org.apache.logging.log4j.core.appender.RollingFileAppender.Builder;
import org.apache.logging.log4j.core.appender.rolling.DirectWriteRolloverStrategy;
import org.apache.logging.log4j.core.appender.rolling.SizeBasedTriggeringPolicy;
import org.apache.logging.log4j.core.appender.rolling.TriggeringPolicy;
import org.apache.logging.log4j.core.appender.rolling.action.Action;
import org.apache.logging.log4j.core.config.AppenderRef;
import org.apache.logging.log4j.core.config.Configuration;
import org.apache.logging.log4j.core.config.LoggerConfig;
import org.apache.logging.log4j.core.config.Property;
import org.apache.logging.log4j.core.impl.Log4jContextFactory;
import org.apache.logging.log4j.core.layout.PatternLayout;
import org.apache.logging.log4j.spi.LoggerContextFactory;
import org.brutusin.instrumentation.Agent;

import com.k2cybersecurity.intcodeagent.models.javaagent.AgentBasicInfo;

public class ConfigLog4J {

	private static final String PROPERTIES_NAME = "properties.name";
	private static final String PROPERTIES_VALUE = "properties.value";
	private static final String APPENDERS_ROLLINGFILE_NAME = "appenders.rollingfile.name";
	private static final String APPENDERS_ROLLINGFILE_PATTERNLAYOUT = "appenders.rollingfile.patternlayout";
	private static final String APPENDER_POLICY_SIZE = "appenders.policies.sizebasedtriggeringpolicy.size";
	private static final String APPENDER_STRATEGY_MAXFILES = "appenders.strategy.maxfiles";
	private static final String APPENDER_STRATEGY_COMPRESSION_LVL = "appenders.strategy.compressionlevel";
	private static final String LOGGER_NAME = "loggers.logger.name";
	private static final String LOGGER_LVL = "loggers.logger.level";
	private static final String LOGGER_APPENDER_REF = "loggers.logger.appenderRef";
	private static final String JCS_LOGGER_NAME = "loggers.jcslogger.name";
	private static final String LOGGER_ADDITIVITY = "loggers.logger.additivity";

	private static ConfigLog4J loggerInstance;
	private Level level;
	private String propertyName;
	private String propertyValue;
	private String appenderName;
	private String appenderPatternlayout;
	private String appenderTriggerPolicySize;
	private String loggerName;
	private String loggerAppenderRef;
	private String jcsLoggerName;
	private String strategyMaxFiles;
	private String stratefyCompressionLevel;
	private String fileName = "/etc/k2-adp/logs/k2_java_agent-" + Agent.applicationUUID + ".log";
	private boolean loggerAdditivity;

	private Class<?>[] classes = { EIDCount.class, EventThreadPool.class, ExecutionMap.class, IPScheduledThread.class,
			LoggingInterceptor.class, ProcessorThread.class, ServletEventPool.class, ServletEventProcessor.class,
			AgentBasicInfo.class };

	private Action[] emptyActions = new Action[0];
	private Object[] emptyObjects = new Object[0];
	private Class<?>[] emptyClasses = new Class<?>[0];

	public ConfigLog4J() {
		Properties props = new Properties();
		try {
			props.load(Thread.currentThread().getContextClassLoader()
					.getResourceAsStream(IAgentConstants.K2_JAVAAGENT_LOG4J_PROPERTIES));
		} catch (IOException e) {
			System.err.println("Error loading Properties!");
		}
		this.propertyName = props.getProperty(PROPERTIES_NAME);
		this.propertyValue = props.getProperty(PROPERTIES_VALUE);
		this.appenderName = props.getProperty(APPENDERS_ROLLINGFILE_NAME);
		this.appenderPatternlayout = props.getProperty(APPENDERS_ROLLINGFILE_PATTERNLAYOUT);
		this.appenderTriggerPolicySize = props.getProperty(APPENDER_POLICY_SIZE);
		this.strategyMaxFiles = props.getProperty(APPENDER_STRATEGY_MAXFILES);
		this.stratefyCompressionLevel = props.getProperty(APPENDER_STRATEGY_COMPRESSION_LVL);
		this.loggerName = props.getProperty(LOGGER_NAME);
		this.loggerAdditivity = Boolean.parseBoolean(props.getProperty(LOGGER_ADDITIVITY));

		String level = props.getProperty(LOGGER_LVL);
		if (level.equals("OFF")) {
			this.level = Level.OFF;
		} else if (level.equals("FATAL")) {
			this.level = Level.FATAL;
		} else if (level.equals("ERROR")) {
			this.level = Level.ERROR;
		} else if (level.equals("WARN")) {
			this.level = Level.WARN;
		} else if (level.equals("INFO")) {
			this.level = Level.INFO;
		} else if (level.equals("DEBUG")) {
			this.level = Level.DEBUG;
		} else if (level.equals("TRACE")) {
			this.level = Level.TRACE;
		} else if (level.equals("ALL")) {
			this.level = Level.ALL;
		}

		this.loggerAppenderRef = props.getProperty(LOGGER_APPENDER_REF);
		this.jcsLoggerName = props.getProperty(JCS_LOGGER_NAME);
	}

	public void initializeLogs() {
		try {
			LoggerContextFactory loggerFactory = new Log4jContextFactory();
			LogManager.setFactory(loggerFactory);
			LoggerContext ctx = (LoggerContext) loggerFactory.getContext(ConfigLog4J.class.getName(), null, null, false);
			
			Configuration config = ctx.getConfiguration();
			Builder builder = RollingFileAppender.newBuilder();
			builder.withName(this.appenderName);
			builder.withFileName(fileName);
			builder.withFilePattern(fileName + ".%i");
			org.apache.logging.log4j.core.layout.PatternLayout.Builder layout = PatternLayout.newBuilder();
			layout.withPattern(this.appenderPatternlayout);
			builder.withLayout(layout.build());
			TriggeringPolicy policy = SizeBasedTriggeringPolicy.createPolicy(this.appenderTriggerPolicySize);
			builder.withPolicy(policy);
			builder.withStrategy(DirectWriteRolloverStrategy.createStrategy(this.strategyMaxFiles,
					this.stratefyCompressionLevel, this.emptyActions, false, config));
			AppenderRef ref = AppenderRef.createAppenderRef(this.loggerAppenderRef, this.level, null);
			AppenderRef[] refs = new AppenderRef[] { ref };
			Property prop = Property.createProperty(this.propertyName, this.propertyValue);
			Property[] properties = new Property[] { prop };
			LoggerConfig loggerConfig = LoggerConfig.createLogger(this.loggerAdditivity, this.level, this.loggerName, "", refs,
					properties, config, null);
			loggerConfig.addAppender(builder.build(), this.level, null);
			config.addLogger(this.loggerName, loggerConfig);
			ctx.updateLoggers(config);	
			updateAllLocalLoggers();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public void updateAllLocalLoggers() {
		for (Class<?> clazz : classes) {
			try {
				Method updateLoggerMethod = clazz.getDeclaredMethod("setLogger", this.emptyClasses);
				updateLoggerMethod.invoke(null, this.emptyObjects);
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}

		}
	}

	public static ConfigLog4J getInstance() {
		if (loggerInstance == null) {
			loggerInstance = new ConfigLog4J();
		}
		return loggerInstance;
	}
	
	public Level getLevel() {
		return this.level;
	}
}
