package com.k2cybersecurity.intcodeagent.filelogging;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.text.SimpleDateFormat;
import java.util.Calendar;

import org.brutusin.instrumentation.Agent;

import com.k2cybersecurity.intcodeagent.properties.K2JALogProperties;

public class LogWriter implements Runnable {

	private static int defaultLogLevel;

	private int logLevel;

	private String logLevelName;

	private String logEntry;

	private String loggingClassName;
	
	private static long maxFileSize;

	Calendar cal = Calendar.getInstance();
	SimpleDateFormat sdf = new SimpleDateFormat(DATE_FORMAT_NOW);

	public static final String DATE_FORMAT_NOW = "yyyy-MM-dd HH:mm:ss";

	private static String fileName;
	
	private static String updatedFileName;
	
	private static int logFileCounter = 0;

	static {
		fileName = "/etc/k2-adp/logs/k2_java_agent-" + Agent.APPLICATION_UUID + ".log";
		updatedFileName = fileName;
		try {
			maxFileSize = K2JALogProperties.maxfilesize * 1048576;
			
			//k2.log.handler.maxfilesize=10
			//k2.log.handler.maxfilesize.unit=MB
			
			String level = K2JALogProperties.level;
			if (level.equals("OFF")) {
				defaultLogLevel = LogLevel.OFF.getLevel();
			} else if (level.equals("SEVERE")) {
				defaultLogLevel = LogLevel.SEVERE.getLevel();
			} else if (level.equals("ERROR")) {
				defaultLogLevel = LogLevel.ERROR.getLevel();
			} else if (level.equals("WARNING")) {
				defaultLogLevel = LogLevel.WARNING.getLevel();
			} else if (level.equals("INFO")) {
				defaultLogLevel = LogLevel.INFO.getLevel();
			} else if (level.equals("DEBUG")) {
				defaultLogLevel = LogLevel.DEBUG.getLevel();
			} else if (level.equals("ALL")) {
				defaultLogLevel = LogLevel.ALL.getLevel();
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public LogWriter(LogLevel logLevel, String logEntry, String loggingClassName) {
		this.logEntry = logEntry;
		this.logLevel = logLevel.getLevel();
		this.logLevelName = logLevel.name();
		this.loggingClassName = loggingClassName;
	}

	@Override
	public void run() {
		if (this.logLevel == 0 || this.logLevel > defaultLogLevel) {
			return;
		}
		StringBuilder sb = new StringBuilder();
		sb.append("K2-LOG : ");
		sb.append(sdf.format(cal.getTime()));
		sb.append(" : ");
		sb.append(this.logLevelName);
		if (this.loggingClassName != null)
			sb.append(" : ");
		sb.append(this.loggingClassName);
		sb.append(" - ");
		sb.append(this.logEntry);
		File file = new File(updatedFileName);
		try (BufferedWriter writer = new BufferedWriter(new FileWriter(updatedFileName, true))) {
			writer.write(sb.toString());
			writer.newLine();
			if(file.length()> maxFileSize) {
				logFileCounter++;
				updatedFileName= fileName + "." + logFileCounter;
			}
		} catch (Throwable e) {
			e.printStackTrace();
		}

	}

}
