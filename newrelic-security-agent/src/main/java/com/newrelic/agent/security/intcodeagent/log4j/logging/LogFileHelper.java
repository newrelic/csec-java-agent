/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package com.newrelic.agent.security.intcodeagent.log4j.logging;

import com.newrelic.agent.security.instrumentator.os.OSVariables;
import com.newrelic.agent.security.instrumentator.os.OsVariablesInstance;

import java.io.File;

/**
 * Utility class to get the New Relic log file.
 */
public class LogFileHelper {

    private static final String NEW_RELIC_LOG_FILE = "newrelic.logfile";
    private static final String LOGS_DIRECTORY = "logs";

    public static final String LOG_DAILY = "log_daily";
    public static final String LOG_FILE_COUNT = "log_file_count";
    public static final String LOG_FILE_NAME = "log_file_name";
    public static final String LOG_FILE_PATH = "log_file_path";
    public static final String LOG_LIMIT = "log_limit_in_kbytes";
    public static final String LOG_LEVEL = "log_level";
    public static final boolean DEFAULT_LOG_DAILY = false;
    public static final int DEFAULT_LOG_FILE_COUNT = 1;
    public static final String DEFAULT_LOG_FILE_NAME = "java-security-collector.log";

    public static final String DEFAULT_LOG_LEVEL = "info";
    public static final int DEFAULT_LOG_LIMIT = 0;

    public static final String STDOUT = "STDOUT";


    private static OSVariables osVariables = OsVariablesInstance.getInstance().getOsVariables();

    public static String getLogFileName() {
        return new File(osVariables.getLogDirectory(), "java-security-collector-new.log").getAbsolutePath();
    }

}
