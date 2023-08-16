package com.nr.instrumentation.security.apache.wicket6;

import com.newrelic.api.agent.security.instrumentation.helpers.URLMappingsHelper;
import com.newrelic.api.agent.security.schema.ApplicationURLMapping;

import java.util.HashMap;
import java.util.Map;

public class WicketHelper {
    private static final String WILDCARD = "*";
    private static final String SEPARATOR = "/";
    private static final Map<Integer, String> packageMap = new HashMap<>();

    public static void getMappings(String[] pathSegments, String handler, boolean isPackageMapper) {
        String path = buildUrl(pathSegments);
        try {
            String finalPath = path + (isPackageMapper ? SEPARATOR + WILDCARD : "");
            URLMappingsHelper.addApplicationURLMapping(new ApplicationURLMapping(WILDCARD, finalPath, handler));
        } catch (Exception ignored){
        }
    }

    public static String buildUrl(String[] mountSegments) {
        StringBuilder path = new StringBuilder();
        try {
            if(mountSegments.length == 0) {
                return SEPARATOR;
            }
            for (String segment: mountSegments) {
                path.append(SEPARATOR).append(segment);
            }
        } catch (Exception ignored) {
        }
        return path.toString();
    }

    public static Map<Integer, String> getPackageMap() {
        return packageMap;
    }

}
