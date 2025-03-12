package com.newrelic.agent.security.util;

public interface IUtilConstants {
    String SECURITY_MODE = "security.mode";
    String RASP = "RASP";

    String IAST = "IAST";
    String IAST_RESTRICTED = "IAST_RESTRICTED";

    String SCAN_TIME_DELAY = "security.scan_schedule.delay";
    String SCAN_TIME_SCHEDULE = "security.scan_schedule.schedule";
    String SCAN_TIME_DURATION = "security.scan_schedule.duration";
    String SCAN_TIME_COLLECT_SAMPLES = "security.scan_schedule.always_sample_traces";
    String SCAN_REQUEST_RATE_LIMIT = "security.scan_controllers.iast_scan_request_rate_limit";

    String SKIP_IAST_SCAN = "security.exclude_from_iast_scan";
    String SKIP_IAST_SCAN_API = SKIP_IAST_SCAN + ".api";
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

    String MONITORING_CRITERIA_MAX_EVENT_QUOTA = "security.monitoring_criteria.event_quota_per_trace";
    String MONITORING_CRITERIA_EVENT_QUOTA_PER_TRACE = "security.monitoring_criteria.event_quota_per_trace";
    String MONITORING_CRITERIA_REPEAT = "security.monitoring_criteria.repeat";

    String RESTRICTION_CRITERIA_ACCOUNT_INFO_ACCOUNT_ID = "security.restriction_criteria.account_info.account_id_value";
    String RESTRICTION_CRITERIA_MAPPING_PARAMETERS = "security.restriction_criteria.mapping_parameters";
    String RESTRICTION_CRITERIA_MAPPING_PARAMETERS_HEADER = RESTRICTION_CRITERIA_MAPPING_PARAMETERS + ".header";
    String RESTRICTION_CRITERIA_MAPPING_PARAMETERS_QUERY = RESTRICTION_CRITERIA_MAPPING_PARAMETERS + ".query";
    String RESTRICTION_CRITERIA_MAPPING_PARAMETERS_BODY = RESTRICTION_CRITERIA_MAPPING_PARAMETERS + ".body";
    String RESTRICTION_CRITERIA_MAPPING_PARAMETERS_PATH = RESTRICTION_CRITERIA_MAPPING_PARAMETERS + ".path";
    String RESTRICTION_CRITERIA_MAPPING_PARAMETERS_HEADER_ENABLED = RESTRICTION_CRITERIA_MAPPING_PARAMETERS_HEADER + ".enabled";
    String RESTRICTION_CRITERIA_MAPPING_PARAMETERS_QUERY_ENABLED = RESTRICTION_CRITERIA_MAPPING_PARAMETERS_QUERY + ".enabled";
    String RESTRICTION_CRITERIA_MAPPING_PARAMETERS_BODY_ENABLED = RESTRICTION_CRITERIA_MAPPING_PARAMETERS_BODY + ".enabled";
    String RESTRICTION_CRITERIA_MAPPING_PARAMETERS_PATH_ENABLED = RESTRICTION_CRITERIA_MAPPING_PARAMETERS_PATH + ".enabled";
    String RESTRICTION_CRITERIA_MAPPING_PARAMETERS_HEADER_LOCATION = RESTRICTION_CRITERIA_MAPPING_PARAMETERS_HEADER + ".location";
    String RESTRICTION_CRITERIA_MAPPING_PARAMETERS_QUERY_LOCATION = RESTRICTION_CRITERIA_MAPPING_PARAMETERS_QUERY + ".location";
    String RESTRICTION_CRITERIA_MAPPING_PARAMETERS_BODY_LOCATION = RESTRICTION_CRITERIA_MAPPING_PARAMETERS_BODY + ".location";
    String RESTRICTION_CRITERIA_STRICT = "security.restriction_criteria.strict";


    String GROUP_NAME = "group-name";
    String INFO = "INFO";
    String OFF = "OFF";
    String NR_LOG_LEVEL = "log_level";
    String LOG_LEVEL = "log-level";


    String DIRECTORY_PERMISSION = "rwxrwx---";

    String FILE_PERMISSIONS = "rw-rw----";

    String NOT_AVAILABLE = "Not Available";

    String NR_SECURITY_ENABLED = "security.enabled";

    String NR_SECURITY_HOME_APP = "security.is_home_app";
    String IAST_TEST_IDENTIFIER = "security.iast_test_identifier";
    String IAST_SCAN_INSTANCE_COUNT = "security.scan_controllers.scan_instance_count";

    String NR_SECURITY_CA_BUNDLE_PATH = "ca_bundle_path";
    String LOG_FILE_PATH = "log_file_path";
    String NR_SECURITY_HOME = "nr-security-home";
    String NR_LOG_DAILY_ROLLOVER_PERIOD = "log.rollover.period";
    String APPLICATION_DIRECTORY = "APPLICATION_DIRECTORY";

    String SERVER_BASE_DIRECTORY = "SERVER_BASE_DIRECTORY";
    String SAME_SITE_COOKIES = "SAME_SITE_COOKIES";

    String APPLICATION_TMP_DIRECTORY = "APPLICATION_TMP_DIRECTORY";
    String JAVA_IO_TMPDIR = "java.io.tmpdir";

}
