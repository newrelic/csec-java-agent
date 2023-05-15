package com.newrelic.api.agent.security.instrumentation.helpers;

import com.newrelic.api.agent.security.schema.HttpRequest;
import com.newrelic.api.agent.security.schema.StringUtils;

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
}
