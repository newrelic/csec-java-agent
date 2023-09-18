/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package com.newrelic.agent.security.intcodeagent.filelogging;

import com.newrelic.agent.security.instrumentator.os.OSVariables;
import com.newrelic.agent.security.instrumentator.os.OsVariablesInstance;
import com.newrelic.api.agent.NewRelic;
import com.newrelic.api.agent.security.schema.StringUtils;

import java.io.File;

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

    public static boolean isLoggingToStdOut() {
        String logFileName = NewRelic.getAgent().getConfig().getValue(LogFileHelper.LOG_FILE_NAME, LogFileHelper.DEFAULT_LOG_FILE_NAME);
        return StringUtils.equals(LogFileHelper.STDOUT, logFileName);
    }

    public static int logFileCount() {
        return Math.max(1, NewRelic.getAgent().getConfig().getValue(LogFileHelper.LOG_FILE_COUNT, LogFileHelper.DEFAULT_LOG_FILE_COUNT));
    }

    public static boolean dailyRollover() {
        return NewRelic.getAgent().getConfig().getValue(LogFileHelper.LOG_DAILY, LogFileHelper.DEFAULT_LOG_DAILY);
    }

}
