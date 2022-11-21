package com.newrelic.agent.security.instrumentator.utils;

import com.newrelic.agent.security.intcodeagent.filelogging.FileLoggerThreadPool;
import com.newrelic.agent.security.intcodeagent.filelogging.LogLevel;
import com.newrelic.agent.security.intcodeagent.properties.K2JAVersionInfo;
import org.apache.commons.lang3.StringUtils;

import java.util.HashMap;
import java.util.Map;

public class EnvLogUtils {
    private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();
    final static Map<String, String> k2Envs = new HashMap<String, String>() {{
        put("K2_AGENT_NODE_CONFIG", System.getenv("K2_AGENT_NODE_CONFIG"));
        put("K2_AGENT_APP_CONFIG", System.getenv("K2_AGENT_APP_CONFIG"));
        put("K2_APP_NAME", System.getenv("K2_APP_NAME"));
        put("K2_APP_VERSION", System.getenv("K2_APP_VERSION"));
        put("K2_APP_TAGS", System.getenv("K2_APP_TAGS"));
        put("ECS_CONTAINER_METADATA_URI", System.getenv("ECS_CONTAINER_METADATA_URI"));
        put("K2_ATTACH", System.getenv("K2_ATTACH"));
        put("K2_HOST_IP", System.getenv("K2_HOST_IP"));
        put("K2_SERVICE_SERVICE_HOST", System.getenv("K2_SERVICE_SERVICE_HOST"));
        put("K2_SERVICE_NAME", System.getenv("K2_SERVICE_NAME"));
        put("KUBERNETES_SERVICE_HOST", System.getenv("KUBERNETES_SERVICE_HOST"));
        put("AWS_EXECUTION_ENV", System.getenv("AWS_EXECUTION_ENV"));
        put("K2_DISABLE", System.getenv("K2_DISABLE"));
        put("K2_GROUP_NAME", System.getenv("K2_GROUP_NAME"));
        put("K2_DYNAMIC_ATTACH", System.getenv("K2_DYNAMIC_ATTACH"));
    }};
    final static String[] requiredK2Envs = {"K2_GROUP_NAME"};

    private static final String LOADING_K2_ENVS_MSG = "[STEP-1][BEGIN][ENV] Current environment variables : %s";
    private static final String LOADED_K2_ENVS_MSG = "[STEP-1][COMPLETE][ENV] Environment information gathering done.";
    private static final String MISSING_K2_ENVS_MSG = "[ENV] Missing mandatory environment variables : %s";

    /**
     * Logs all k2 env vars loaded
     */
    public static void logK2Env() {
        logger.logInit(LogLevel.INFO,
                String.format(LOADING_K2_ENVS_MSG, StringUtils.join(k2Envs)),
                EnvLogUtils.class.getName());
        for(String env: requiredK2Envs) {
            if (StringUtils.isBlank(k2Envs.get(env))) {
                logger.logInit(LogLevel.INFO,
                        String.format(MISSING_K2_ENVS_MSG, env),
                        EnvLogUtils.class.getName());
            }
        }
        logger.logInit(LogLevel.INFO,
                String.format(LOADED_K2_ENVS_MSG, StringUtils.join(k2Envs)),
                EnvLogUtils.class.getName());
        logger.logInit(LogLevel.INFO,
                String.format("K2 JA collector version : %s , json version : %s and build number : %s", K2JAVersionInfo.collectorVersion, K2JAVersionInfo.jsonVersion, K2JAVersionInfo.buildNumber),
                EnvLogUtils.class.getName());
    }

}
