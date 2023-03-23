package com.newrelic.agent.security.intcodeagent.filelogging;

import com.newrelic.agent.security.AgentInfo;
import com.newrelic.agent.security.instrumentator.os.OSVariables;
import com.newrelic.agent.security.instrumentator.os.OsVariablesInstance;
import com.newrelic.agent.security.intcodeagent.utils.CommonUtils;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;

import java.io.*;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.text.SimpleDateFormat;
import java.time.Instant;
import java.util.Calendar;
import java.util.concurrent.TimeUnit;

public class LogWriter implements Runnable {

    private static final String STRING_DOT = ".";

    private static final String STR_HYPHEN = " - ";

    private static final String STR_COLON = " : ";

    private static final String K2_LOG = "K2-LOG : ";
    public static final String THREAD_NAME_TEMPLATE = " [%s] [%s] ";
    public static final String CAUSED_BY = "Caused by: ";

    public static int defaultLogLevel = LogLevel.INFO.getLevel();
    private static long lastRolloverCheckTime = 0L;
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

    private static BufferedWriter writer;

    private static final File currentLogFile;

    private String threadName;

    private static OSVariables osVariables = OsVariablesInstance.getInstance().getOsVariables();

    private static boolean createLogFile() {
        CommonUtils.forceMkdirs(currentLogFile.getParentFile().toPath(), "rwxrwxrwx");

        try {
            currentLogFile.setReadable(true, false);
            writer = new BufferedWriter(new FileWriter(currentLogFileName, true));

            maxFileSize = FileLoggerThreadPool.getInstance().maxfilesize * 1048576;

            if (!osVariables.getWindows()) {
                Files.setPosixFilePermissions(currentLogFile.toPath(), PosixFilePermissions.fromString("rw-rw-rw-"));
            }

        } catch (Throwable e) {
            if (FileLoggerThreadPool.getInstance().isLoggingActive()) {
                //TODO report to cloud
                FileLoggerThreadPool.getInstance().setLoggingActive(false);
            }
            String tmpDir = System.getProperty("java.io.tmpdir");
            System.err.println("[K2-JA] Unable to create log file!!! Please find the error in  " + tmpDir + File.separator + "K2-Logger.err");
            try {
                e.printStackTrace(new PrintStream(tmpDir + File.separator + "K2-Logger.err"));
            } catch (FileNotFoundException ex) {
            }
            return false;
        }
        return true;
    }

    static {
        fileName = new File(osVariables.getLogDirectory(), "java-security-collector.log").getAbsolutePath();
        currentLogFile = new File(fileName);
        currentLogFileName = fileName;
        createLogFile();
    }

    public LogWriter(LogLevel logLevel, String logEntry, String loggingClassName, String threadName) {
        this.logEntry = logEntry;
        this.logLevel = logLevel.getLevel();
        this.logLevelName = logLevel.name();
        this.loggingClassName = loggingClassName;
        this.threadName = threadName;
    }

    public LogWriter(LogLevel logLevel, String logEntry, Throwable throwableLogEntry, String loggingClassName, String threadName) {
        this.throwableLogEntry = throwableLogEntry;
        this.logEntry = logEntry;
        this.logLevel = logLevel.getLevel();
        this.logLevelName = logLevel.name();
        this.loggingClassName = loggingClassName;
        this.threadName = threadName;
    }

    @Override
    public void run() {
        if (this.logLevel == 1 || this.logLevel > defaultLogLevel) {
            return;
        }
        StringBuilder sb = new StringBuilder();
//		sb.append(K2_LOG);
        sb.append(sdf.format(cal.getTime()));
        sb.append(STR_COLON);
        sb.append(String.format(THREAD_NAME_TEMPLATE, AgentInfo.getInstance().getVMPID(), threadName));
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
                sb.append(CAUSED_BY);
                sb.append(this.throwableLogEntry.getCause().getMessage());
                sb.append(StringUtils.LF);
                sb.append(StringUtils.join(this.throwableLogEntry.getCause().getStackTrace(), StringUtils.LF));
                sb.append(StringUtils.LF);
                cause = cause.getCause();
            }
        }
        sb.append(StringUtils.LF);
        try {

//            if (!currentLogFile.isFile()) {
//                createLogFile();
//            }
//			System.out.println(sb.toString());
            writer.write(sb.toString());
            writer.flush();
            FileLoggerThreadPool.getInstance().setLoggingActive(true);

//			writer.newLine();
            rollover(currentLogFileName);
        } catch (IOException e) {
            if (FileLoggerThreadPool.getInstance().isLoggingActive()) {
                //TODO report to cloud
                FileLoggerThreadPool.getInstance().setLoggingActive(false);
            }
        }
    }

    private static void rollover(String fileName) throws IOException {
        if (!rolloverCheckNeeded()) {
            return;
        }

        File currentFile = new File(fileName);
        // TODO: we should check file size using FS meta.
        try {
            writer.close();
            if (Files.size(currentFile.toPath()) > maxFileSize) {
                try (FileLock lock = FileChannel.open(currentFile.toPath(), StandardOpenOption.WRITE).lock()) {
                    if (lock.isValid() && currentFile.exists() && Files.size(currentFile.toPath()) > maxFileSize) {
                        File rolloverFile = new File(fileName + STRING_DOT + Instant.now().toEpochMilli());
                        FileUtils.moveFile(currentFile, rolloverFile);
                    }
                    lock.release();
                } catch (IOException e) {
                }

                CommonUtils.deleteRolloverLogFiles(currentFile.getName(), FileLoggerThreadPool.getInstance().maxfiles);
            }
        } finally {
            writer = new BufferedWriter(new FileWriter(currentFile, true));
            currentFile.setReadable(true, false);
            currentFile.setWritable(true, false);
            if (!osVariables.getWindows()) {
                Files.setPosixFilePermissions(currentFile.toPath(), PosixFilePermissions.fromString("rw-rw-rw-"));
            }
        }


    }

    private static boolean rolloverCheckNeeded() {
        long currTimeMilli = Instant.now().toEpochMilli();
        if (currTimeMilli - lastRolloverCheckTime > TimeUnit.SECONDS.toMillis(30)) {
            lastRolloverCheckTime = currTimeMilli;
            return true;
        }
        return false;
    }

    public static void setLogLevel(LogLevel logLevel) {
        defaultLogLevel = logLevel.getLevel();
    }

    public static String getFileName() {
        return fileName;
    }

}