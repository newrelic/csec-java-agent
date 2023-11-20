package com.newrelic.api.agent.security.instrumentation.helpers;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.schema.HttpRequest;
import com.newrelic.api.agent.security.schema.SecurityMetaData;
import com.newrelic.api.agent.security.schema.StringUtils;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

public class LowSeverityHelper {
    public static final String LOW_SEVERITY_HOOKS_ENABLED = "security.low-priority-instrumentation.enabled";
    public static final boolean DEFAULT = false;

    private static Set<Integer> encounteredLowSeverityEventURIHash = ConcurrentHashMap.newKeySet();

    public static boolean addLowSeverityEventToEncounteredList(Integer urlHashCode, String method) {
        return encounteredLowSeverityEventURIHash.add(StringUtils.join(urlHashCode, method).hashCode());
    }

    public static boolean checkIfLowSeverityEventAlreadyEncountered(Integer urlHashCode, String method) {
        return encounteredLowSeverityEventURIHash.contains(StringUtils.join(urlHashCode, method).hashCode());
    }

    public static void clearLowSeverityEventFilter() {
        encounteredLowSeverityEventURIHash.clear();
    }


    public static boolean addRrequestUriToEventFilter(HttpRequest request) {
        if(request!= null && StringUtils.isNotBlank(request.getUrl())) {
            return addLowSeverityEventToEncounteredList(request.getUrl().hashCode(), request.getMethod());
        }
        return false;
    }

    public static boolean isOwaspHookProcessingNeeded(){
        SecurityMetaData securityMetaData = NewRelicSecurity.getAgent().getSecurityMetaData();
        if(NewRelicSecurity.isHookProcessingActive() && securityMetaData != null) {
            String requestURL = securityMetaData.getRequest().getUrl();
            return (securityMetaData.getFuzzRequestIdentifier() != null && securityMetaData.getFuzzRequestIdentifier().getK2Request())
                    || (StringUtils.isNotBlank(requestURL) && !LowSeverityHelper.checkIfLowSeverityEventAlreadyEncountered(requestURL.hashCode(), securityMetaData.getRequest().getMethod()));
        }
        return false;
    }
}
