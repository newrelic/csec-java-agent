package com.newrelic.agent.security.util;

public interface IUtilConstants {
    String K_2_GROUP_NAME = "K2_GROUP_NAME";
    String SECURITY_MODE = "security.mode";
    String RASP = "RASP";

    String IAST = "IAST";
    String IAST_RESTRICTED = "IAST_RESTRICTED";

    String SCAN_TIME_DELAY = "security.scan_schedule.delay";
    String SCAN_TIME_SCHEDULE = "security.scan_schedule.schedule";
    String SCAN_TIME_DURATION = "security.scan_schedule.duration";
    String SCAN_TIME_COLLECT_SAMPLES = "security.scan_schedule.always_sample_traces";

    String SKIP_IAST_SCAN = "security.exclude_from_iast_scan";
    String SKIP_IAST_SCAN_API = SKIP_IAST_SCAN + ".api";
    String SKIP_IAST_SCAN_PARAMETERS = SKIP_IAST_SCAN + ".http_request_parameters";
    String SKIP_IAST_SCAN_PARAMETERS_HEADER = SKIP_IAST_SCAN + ".http_request_parameters.header";
    String SKIP_IAST_SCAN_PARAMETERS_QUERY = SKIP_IAST_SCAN + ".http_request_parameters.query";
    String SKIP_IAST_SCAN_PARAMETERS_BODY = SKIP_IAST_SCAN + ".http_request_parameters.body";
    String SKIP_IAST_SCAN_PARAMETERS_IAST_DETECTION_CATEGORY = SKIP_IAST_SCAN + ".iast_detection_category";
    String SKIP_INSECURE_SETTINGS = SKIP_IAST_SCAN_PARAMETERS_IAST_DETECTION_CATEGORY + ".insecure_settings";
    String SKIP_INVALID_FILE_ACCESS = SKIP_IAST_SCAN_PARAMETERS_IAST_DETECTION_CATEGORY + ".invalid_file_access";
    String SKIP_SQL_INJECTION = SKIP_IAST_SCAN_PARAMETERS_IAST_DETECTION_CATEGORY + ".sql_injection";
    String SKIP_NOSQL_INJECTION = SKIP_IAST_SCAN_PARAMETERS_IAST_DETECTION_CATEGORY + ".nosql_injection";
    String SKIP_LDAP_INJECTION = SKIP_IAST_SCAN_PARAMETERS_IAST_DETECTION_CATEGORY + ".ldap_injection";
    String SKIP_JAVASCRIPT_INJECTION = SKIP_IAST_SCAN_PARAMETERS_IAST_DETECTION_CATEGORY + ".javascript_injection";
    String SKIP_COMMAND_INJECTION = SKIP_IAST_SCAN_PARAMETERS_IAST_DETECTION_CATEGORY + ".command_injection";
    String SKIP_XPATH_INJECTION = SKIP_IAST_SCAN_PARAMETERS_IAST_DETECTION_CATEGORY + ".xpath_injection";
    String SKIP_SSRF = SKIP_IAST_SCAN_PARAMETERS_IAST_DETECTION_CATEGORY + ".ssrf";
    String SKIP_RXSS = SKIP_IAST_SCAN_PARAMETERS_IAST_DETECTION_CATEGORY + ".rxss";

    String RESTRICTION_CRITERIA_SCAN_TIME_SCHEDULE = "security.restriction_criteria.scan_time.schedule";
    String RESTRICTION_CRITERIA_SCAN_TIME_DURATION = "security.restriction_criteria.scan_time.duration";
    String RESTRICTION_CRITERIA = "security.restriction_criteria";
    String RESTRICTION_CRITERIA_ACCOUNT_INFO_ACCOUNT_ID = "security.restriction_criteria.account_info.account_id_value";
    String RESTRICTION_CRITERIA_MAPPING_PARAMETERS = "security.restriction_criteria.mapping_parameters";
    String RESTRICTION_CRITERIA_SKIP_SCAN_PARAMETERS = "security.restriction_criteria.skip_scan_parameters";
    String RESTRICTION_CRITERIA_SKIP_SCAN_PARAMETERS_HEADER = "security.restriction_criteria.skip_scan_parameters.header";
    String RESTRICTION_CRITERIA_SKIP_SCAN_PARAMETERS_QUERY = "security.restriction_criteria.skip_scan_parameters.query";
    String RESTRICTION_CRITERIA_SKIP_SCAN_PARAMETERS_BODY = "security.restriction_criteria.skip_scan_parameters.body";
    String RESTRICTION_CRITERIA_STRICT = "security.restriction_criteria.strict";


    String GROUP_NAME = "group-name";
    String INFO = "INFO";
    String OFF = "OFF";
    String K_2_LOG_LEVEL = "K2_LOG_LEVEL";
    String NR_LOG_LEVEL = "log_level";
    String LOG_LEVEL = "log-level";

    String PERMISSIONS_ALL = "rwxrwxrwx";

    String DIRECTORY_PERMISSION = "rwxrwx---";

    String FILE_PERMISSIONS = "rw-rw----";

    String NOT_AVAILABLE = "Not Available";

    String NR_SECURITY_ENABLED = "security.enabled";

    String NR_SECURITY_HOME_APP = "security.is_home_app";

    String NR_SECURITY_CA_BUNDLE_PATH = "ca_bundle_path";
    String NR_CSEC_DEBUG_LOGFILE_SIZE = "NR_CSEC_DEBUG_LOGFILE_SIZE";
    String NR_CSEC_DEBUG_LOGFILE_MAX_COUNT = "NR_CSEC_DEBUG_LOGFILE_MAX_COUNT";
    String LOG_FILE_PATH = "log_file_path";
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
