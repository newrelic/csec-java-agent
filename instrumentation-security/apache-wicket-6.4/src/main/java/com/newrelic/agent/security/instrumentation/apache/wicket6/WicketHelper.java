package com.newrelic.agent.security.instrumentation.apache.wicket6;

import com.newrelic.api.agent.security.instrumentation.helpers.URLMappingsHelper;
import com.newrelic.api.agent.security.schema.ApplicationURLMapping;

import java.util.HashMap;
import java.util.Map;

public class WicketHelper {
    private static final String WILDCARD = "*";
    private static final String SEPARATOR = "/";
    private static final Map<Integer, String> packageMap = new HashMap<>();

    public static void getMappings(String path, String handler, boolean isPackageMapper) {
        try {
            String finalPath = path + (isPackageMapper ? SEPARATOR + WILDCARD : "");
            URLMappingsHelper.addApplicationURLMapping(new ApplicationURLMapping(WILDCARD, finalPath, handler));
        } catch (Exception ignored){
        }
    }

    public static Map<Integer, String> getPackageMap() {
        return packageMap;
    }

}
