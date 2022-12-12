package com.newrelic.api.agent.security.utils;

import com.newrelic.api.agent.security.schema.StringUtils;

public class SSRFUtils {

    public static String generateTracingHeaderValue(String previousValue, String apiId, String executionId, String applicationUUID) {

        if (StringUtils.isNotBlank(previousValue)) {
            previousValue = StringUtils.appendIfMissing(previousValue, ";");
        }
        return String.format("%s%s/%s/%s;", previousValue, applicationUUID, apiId, executionId);
    }
}
