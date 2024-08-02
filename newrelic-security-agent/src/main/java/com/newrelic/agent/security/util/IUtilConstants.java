package com.newrelic.agent.security.util;

public interface IUtilConstants {
    String K_2_GROUP_NAME = "K2_GROUP_NAME";
    String SECURITY_MODE = "security.mode";
    String RASP = "RASP";

    String IAST = "IAST";
    String IAST_RESTRICTED = "IAST_RESTRICTED";

    String RESTRICTION_CRITERIA_SCAN_TIME = "security.restriction_criteria.scan_time";
    String RESTRICTION_CRITERIA_SCAN_TIME_SCHEDULE = "security.restriction_criteria.scan_time.schedule";
    String RESTRICTION_CRITERIA_SCAN_TIME_DURATION = "security.restriction_criteria.scan_time.duration";
    String RESTRICTION_CRITERIA = "security.restriction_criteria";
    String RESTRICTION_CRITERIA_ACCOUNT_INFO_ACCOUNT_ID = "security.restriction_criteria.account_info.account_id";
    String RESTRICTION_CRITERIA_MAPPING_PARAMETERS = "security.restriction_criteria.mapping_parameters";
    String RESTRICTION_CRITERIA_SKIP_SCAN_PARAMETERS = "security.restriction_criteria.skip_scan_parameters";
    String RESTRICTION_CRITERIA_SKIP_SCAN_PARAMETERS_HEADER = "security.restriction_criteria.skip_scan_parameters.header";
    String RESTRICTION_CRITERIA_SKIP_SCAN_PARAMETERS_QUERY = "security.restriction_criteria.skip_scan_parameters.query";
    String RESTRICTION_CRITERIA_SKIP_SCAN_PARAMETERS_BODY = "security.restriction_criteria.skip_scan_parameters.body";
    String RESTRICTION_CRITERIA_STRICT = "security.restriction_criteria.strict";


    String GROUP_NAME = "group-name";
    String INFO = "INFO";
    String K_2_LOG_LEVEL = "K2_LOG_LEVEL";
    String NR_LOG_LEVEL = "log_level";
    String LOG_LEVEL = "log-level";

    String PERMISSIONS_ALL = "rwxrwxrwx";

    String DIRECTORY_PERMISSION = "rwxrwx---";

    String FILE_PERMISSIONS = "rw-rw----";

    String NOT_AVAILABLE = "Not Available";

    String NR_SECURITY_ENABLED = "security.enabled";

    String NR_SECURITY_HOME_APP = "security.is_home_app";

    String NR_SECURITY_CA_BUNDLE_PATH = "security.ca_bundle_path";
    String NR_CSEC_DEBUG_LOGFILE_SIZE = "NR_CSEC_DEBUG_LOGFILE_SIZE";
    String NR_CSEC_DEBUG_LOGFILE_MAX_COUNT = "NR_CSEC_DEBUG_LOGFILE_MAX_COUNT";
    String NR_SECURITY_HOME = "nr-security-home";
    String PROCESSED = "PROCESSED";
    String ERROR = "ERROR";
    String SENT = "SENT";
    String REJECTED = "REJECTED";
    String NR_LOG_DAILY_ROLLOVER_PERIOD = "log.rollover.period";
    String APPLICATION_DIRECTORY = "APPLICATION_DIRECTORY";

    String SERVER_BASE_DIRECTORY = "SERVER_BASE_DIRECTORY";
    String SAME_SITE_COOKIES = "SAME_SITE_COOKIES";

    String APPLICATION_TMP_DIRECTORY = "APPLICATION_TMP_DIRECTORY";
    String JAVA_IO_TMPDIR = "java.io.tmpdir";
}
