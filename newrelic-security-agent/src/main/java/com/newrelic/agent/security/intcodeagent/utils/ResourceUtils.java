package com.newrelic.agent.security.intcodeagent.utils;

import com.newrelic.agent.security.intcodeagent.filelogging.FileLoggerThreadPool;
import com.newrelic.api.agent.security.Agent;
import com.newrelic.api.agent.security.utils.logging.LogLevel;

import java.io.InputStream;
import java.net.URL;

public class ResourceUtils {

    private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

    public static InputStream getResourceStreamFromAgentJar(String resourceName) {
        try {
            return new URL("jar:" + Agent.getAgentJarURL().toExternalForm() + "!/" + resourceName).openStream();
        } catch (Exception e) {
            logger.log(LogLevel.SEVERE, String.format("Unable to locate resource from agent jar : %s", e.getMessage()), CommonUtils.class.getName());
            logger.log(LogLevel.FINER, "Unable to locate resource from agent jar : ", e, CommonUtils.class.getName());
        }
        return null;
    }
}
