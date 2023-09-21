/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package com.newrelic.agent.security.intcodeagent.filelogging;

import com.newrelic.agent.security.instrumentator.os.OsVariablesInstance;
import com.newrelic.api.agent.NewRelic;
import com.newrelic.api.agent.security.schema.StringUtils;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.comparator.LastModifiedFileComparator;
import org.apache.commons.io.filefilter.FileFilterUtils;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collection;

/**
 * Utility class to get the New Relic log file.
 */
public class LogFileHelper {

    public static final String LOG_DAILY = "log_daily";
    public static final String LOG_FILE_COUNT = "log_file_count";
    public static final String LOG_FILE_NAME = "log_file_name";
    public static final boolean DEFAULT_LOG_DAILY = false;
    public static final int DEFAULT_LOG_FILE_COUNT = 1;
    public static final String DEFAULT_LOG_FILE_NAME = "java-security-collector.log";

    public static final String STDOUT = "STDOUT";

    private static final String STRING_DOT = ".";

    public static boolean isLoggingToStdOut() {
        String logFileName = NewRelic.getAgent().getConfig().getValue(LogFileHelper.LOG_FILE_NAME, LogFileHelper.DEFAULT_LOG_FILE_NAME);
        return StringUtils.equals(LogFileHelper.STDOUT, logFileName);
    }

    public static int logFileCount() {
        return Math.max(1, NewRelic.getAgent().getConfig().getValue(LogFileHelper.LOG_FILE_COUNT, LogFileHelper.DEFAULT_LOG_FILE_COUNT));
    }

    public static boolean isDailyRollover() {
        return NewRelic.getAgent().getConfig().getValue(LogFileHelper.LOG_DAILY, LogFileHelper.DEFAULT_LOG_DAILY);
    }

    public static void deleteRolloverLogFiles(String fileName, int max) {
        Collection<File> rolloverLogFiles = FileUtils.listFiles(new File(OsVariablesInstance.getInstance().getOsVariables().getLogDirectory()), FileFilterUtils.prefixFileFilter(fileName + "."), null);

        if (rolloverLogFiles.size() > max) {
            File[] sortedLogFiles = rolloverLogFiles.toArray(new File[0]);
            Arrays.sort(sortedLogFiles, LastModifiedFileComparator.LASTMODIFIED_COMPARATOR);
            for (int i = 0; i < sortedLogFiles.length - max; i++) {
                FileUtils.deleteQuietly(sortedLogFiles[i]);
            }
        }
    }

    public static BufferedWriter dailyRollover(String fileName) throws IOException {
        File currentFile = new File(fileName);
        try {
            File rolloverFile = new File(fileName + STRING_DOT + Instant.now().toEpochMilli());
            FileUtils.moveFile(currentFile, rolloverFile);
            deleteRolloverLogFiles(currentFile.getName(), FileLoggerThreadPool.getInstance().maxfiles);
            currentFile.setReadable(true, false);
            currentFile.setWritable(true, false);
            if (!OsVariablesInstance.getInstance().getOsVariables().getWindows()) {
                Files.setPosixFilePermissions(currentFile.toPath(), PosixFilePermissions.fromString("rw-rw-rw-"));
            }
        } catch (IOException e) {
        }
        return new BufferedWriter(new FileWriter(currentFile, true));
    }

    public static void performDailyRollover(){
        try {
            InitLogWriter.setWriter(dailyRollover(InitLogWriter.getFileName()));
        } catch (IOException e) {
            FileLoggerThreadPool.getInstance().setInitLoggingActive(false);
        }
        try {
            LogWriter.setWriter(dailyRollover(LogWriter.getFileName()));
        } catch (IOException e) {
            FileLoggerThreadPool.getInstance().setLoggingActive(false);
        }

    }
}
