package com.k2cybersecurity.intcodeagent.filelogging;

import com.k2cybersecurity.instrumentator.K2Instrumentator;
import com.k2cybersecurity.instrumentator.httpclient.HttpClient;
import com.k2cybersecurity.instrumentator.httpclient.IRestClientConstants;
import com.k2cybersecurity.instrumentator.os.OSVariables;
import com.k2cybersecurity.instrumentator.os.OsVariablesInstance;
import com.k2cybersecurity.intcodeagent.properties.K2JALogProperties;
import com.k2cybersecurity.intcodeagent.utils.CommonUtils;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.attribute.PosixFilePermissions;
import java.text.SimpleDateFormat;
import java.time.Instant;
import java.util.Calendar;
import java.util.HashMap;
import java.util.Map;
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

    private static int logFileCounter = 0;

    private static BufferedWriter writer;

    private static final File currentLogFile;

    private String threadName;

    private static OSVariables osVariables = OsVariablesInstance.getInstance().getOsVariables();

    private static boolean createLogFile() {
        CommonUtils.forceMkdirs(currentLogFile.getParentFile().toPath(), "rwxrwxrwx");

        try {
            currentLogFile.setReadable(true, false);
            writer = new BufferedWriter(new FileWriter(currentLogFileName, true));

            maxFileSize = K2JALogProperties.maxfilesize * 1048576;

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
        fileName = new File(osVariables.getLogDirectory(), "k2-java-agent.log").getAbsolutePath();
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
        sb.append(String.format(THREAD_NAME_TEMPLATE, K2Instrumentator.VMPID, threadName));
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
        if (Files.size(currentFile.toPath()) > maxFileSize) {
            writer.close();
            logFileCounter++;
            File rolloverFile = new File(fileName + STRING_DOT + logFileCounter);
            currentFile.renameTo(rolloverFile);
            writer = new BufferedWriter(new FileWriter(currentLogFileName, true));

            currentFile.setReadable(true, false);
            if (!osVariables.getWindows()) {
                Files.setPosixFilePermissions(currentFile.toPath(), PosixFilePermissions.fromString("rw-rw-rw-"));
            }
            uploadLogsAndDeleteFile(rolloverFile);
            int removeFile = logFileCounter - K2JALogProperties.maxfiles;
            if (removeFile > 0) {
                File remove = new File(fileName + STRING_DOT + removeFile);
                if (remove.exists()) {
                    FileUtils.deleteQuietly(remove);
                }
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

    private static void uploadLogsAndDeleteFile(File file) {
        Map<String, String> queryParams = new HashMap<>();
        queryParams.put("applicationUUID", K2Instrumentator.APPLICATION_UUID);
        queryParams.put("saveName", file.getName());
        HttpClient.getInstance().doPost(IRestClientConstants.COLLECTOR_UPLOAD_LOG, null, queryParams, null, file);
    }

    public static String getFileName() {
        return fileName;
    }

}
