package com.newrelic.agent.security.instrumentation.apache.wicket7;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.URLMappingsHelper;
import com.newrelic.api.agent.security.schema.ApplicationURLMapping;

public class WicketHelper {
    private static final String WILDCARD = "*";

    private static final String SEPARATOR = "/";

    public static void getMappings(String path, String handler, boolean isPackageMapper) {
        try{
            if (!NewRelicSecurity.getAgent().isSecurityEnabled()) {
                return;
            }
            if(!path.startsWith(SEPARATOR)) {
                path = SEPARATOR + path;
            }

            if(isPackageMapper){
                String finalPath = path + SEPARATOR + WILDCARD;
                URLMappingsHelper.addApplicationURLMapping(new ApplicationURLMapping(WILDCARD, finalPath, handler));
            } else {
                URLMappingsHelper.addApplicationURLMapping(new ApplicationURLMapping(WILDCARD, path, handler));
            }
        } catch (Exception ignored){
        }
    }
}
