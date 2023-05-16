package com.newrelic.api.agent.security.instrumentation.helpers;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.schema.HttpRequest;
import com.newrelic.api.agent.security.schema.SecurityMetaData;
import com.newrelic.api.agent.security.schema.StringUtils;

import java.security.MessageDigest;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

public class LowSeverityHelper {
    public static final String LOW_SEVERITY_HOOKS_ENABLED = "security.low_severity_hooks.enabled";
    public static final boolean DEFAULT = true;

    private static Set<Integer> encounteredLowSeverityEventURIHash = ConcurrentHashMap.newKeySet();

    public static boolean addLowSeverityEventToEncounteredList(Integer owaspEventApiId) {
        return encounteredLowSeverityEventURIHash.add(owaspEventApiId);
    }

    public static boolean checkIfLowSeverityEventAlreadyEncountered(Integer eventApiId) {
        return encounteredLowSeverityEventURIHash.contains(eventApiId);
    }

    public static void clearLowSeverityEventFilter() {
        encounteredLowSeverityEventURIHash.clear();
    }


    public static boolean addRrequestUriToEventFilter(HttpRequest request) {
        if(request!= null && StringUtils.isNotBlank(request.getUrl())) {
            return addLowSeverityEventToEncounteredList(request.getUrl().hashCode());
        }
        return false;
    }

    public static boolean isOwaspHookProcessingNeeded(){
        SecurityMetaData securityMetaData = NewRelicSecurity.getAgent().getSecurityMetaData();
        if(securityMetaData != null) {
            String requestURL = securityMetaData.getRequest().getUrl();
            return (securityMetaData.getFuzzRequestIdentifier() != null && securityMetaData.getFuzzRequestIdentifier().getK2Request())
                    || (StringUtils.isNotBlank(requestURL) && !LowSeverityHelper.checkIfLowSeverityEventAlreadyEncountered(requestURL.hashCode()));
        }
        return false;
    }
}
