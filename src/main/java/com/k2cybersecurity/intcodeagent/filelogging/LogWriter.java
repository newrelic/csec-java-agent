package com.k2cybersecurity.intcodeagent.filelogging;

import com.k2cybersecurity.instrumentator.K2Instrumentator;
import com.k2cybersecurity.intcodeagent.properties.K2JALogProperties;
import com.k2cybersecurity.intcodeagent.websocket.FtpClient;
import org.apache.commons.lang3.StringUtils;

import java.io.*;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.TimeUnit;

public class LogWriter implements Runnable {

	private static final String STRING_DOT = ".";

	private static final String STR_HYPHEN = " - ";

	private static final String STR_COLON = " : ";

	private static final String K2_LOG = "K2-LOG : ";

	private static int defaultLogLevel;

	private int logLevel;

	private String logLevelName;

	private String logEntry;

	private Throwable throwableLogEntry;

	private String loggingClassName;

	private static long maxFileSize;

	Calendar cal = Calendar.getInstance();
	SimpleDateFormat sdf = new SimpleDateFormat(DATE_FORMAT_NOW);

	public static final String DATE_FORMAT_NOW = "yyyy-MM-dd HH:mm:ss";

	private static final String fileName;

	private static final String currentLogFileName;

	private static int logFileCounter = 0;

	private static BufferedWriter writer;

	private static final File currentLogFile;

	static {
		fileName = "/tmp/k2_java_agent-" + K2Instrumentator.APPLICATION_UUID + ".log";
		currentLogFile = new File(fileName);
		currentLogFileName = fileName;
		try {
			writer = new BufferedWriter(new FileWriter(currentLogFileName, true));
			maxFileSize = K2JALogProperties.maxfilesize * 1048576;

			// k2.log.handler.maxfilesize=10
			// k2.log.handler.maxfilesize.unit=MB

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
//			e.printStackTrace();
		}
	}

	public LogWriter(LogLevel logLevel, String logEntry, String loggingClassName) {
		this.logEntry = logEntry;
		this.logLevel = logLevel.getLevel();
		this.logLevelName = logLevel.name();
		this.loggingClassName = loggingClassName;
	}

	public LogWriter(LogLevel logLevel, String logEntry, Throwable throwableLogEntry, String loggingClassName) {
		this.throwableLogEntry = throwableLogEntry;
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
		sb.append(K2_LOG);
		sb.append(sdf.format(cal.getTime()));
		sb.append(STR_COLON);
		sb.append(this.logLevelName);
		if (this.loggingClassName != null)
			sb.append(STR_COLON);
		sb.append(this.loggingClassName);
		sb.append(STR_HYPHEN);
		if (this.logEntry != null)
			sb.append(this.logEntry);
		if (this.throwableLogEntry != null) {
//			this.throwableLogEntry.printStackTrace();
			sb.append(this.throwableLogEntry.toString());
			sb.append(StringUtils.LF);
			sb.append(StringUtils.join(this.throwableLogEntry.getStackTrace(), StringUtils.LF));
			sb.append(StringUtils.LF);
			Throwable cause = this.throwableLogEntry.getCause();
			while (cause != null) {
				sb.append("Caused by: ");
				sb.append(this.throwableLogEntry.getCause().getMessage());
				sb.append(StringUtils.LF);
				sb.append(StringUtils.join(this.throwableLogEntry.getCause().getStackTrace(), StringUtils.LF));
				sb.append(StringUtils.LF);
				cause = cause.getCause();
			}
		}
		sb.append(StringUtils.LF);
		try {
			writer.write(sb.toString());
			writer.flush();

//			writer.newLine();
			rollover(currentLogFile);
		} catch (IOException e) {
//			e.printStackTrace();
		}

	}

	private static void rollover(File currentFile) throws IOException {
		if (currentFile.length() > maxFileSize) {
			writer.close();
			logFileCounter++;
			File rolloverFile = new File(fileName + STRING_DOT + logFileCounter);
			currentFile.renameTo(rolloverFile);
			
			uploadLogsAndDeleteFile(rolloverFile);
			
			PrintWriter pw = new PrintWriter(new File(currentLogFileName));
			pw.write(StringUtils.EMPTY);
			pw.close();

			writer = new BufferedWriter(new FileWriter(currentLogFileName, true));

			int removeFile = logFileCounter - K2JALogProperties.maxfiles;
			if (removeFile > 0) {
				File remove = new File(fileName + STRING_DOT + removeFile);
				if (remove.exists())
					remove.delete();
			}
		}
	}

	public static void updateLogLevel(LogLevel logLevel, TimeUnit timeUnit, Integer duration ) {
		final int currentLogLevel = defaultLogLevel;
		defaultLogLevel = logLevel.getLevel();
		new Timer().schedule(new TimerTask() {
			@Override
			public void run() {
				defaultLogLevel = currentLogLevel;
			}
		}, timeUnit.toMillis(duration));

	}
	public static void setLogLevel(LogLevel logLevel) {
		defaultLogLevel = logLevel.getLevel();
	}
	
	private static void uploadLogsAndDeleteFile(File file) {
		boolean result = FtpClient.sendLogFile(file);
		if (result) {
			file.delete();
		}
		
	}
	
	public static String getFileName() {
		return fileName;
	}
	
}
