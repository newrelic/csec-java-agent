package com.newrelic.agent.security.intcodeagent.utils;

import com.newrelic.agent.security.intcodeagent.filelogging.FileLoggerThreadPool;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import com.newrelic.api.agent.security.Agent;
import org.apache.commons.io.FileUtils;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.SecureRandom;
import java.util.Stack;

public class CommonUtils {

    private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();
    public static final String POLICY_WRITE_FAILED = "policy write failed : ";
    public static final String POLICY_WRITTEN_TO_FILE = "policy written to file : ";

    public static SecureRandom secureRandom = new SecureRandom();

    public static Boolean forceMkdirs(Path directory, String permissions) throws IOException {
        File existingDirectory = directory.toFile();
        Stack<String> pathStack = new Stack<>();
        while (!existingDirectory.isDirectory()) {
            pathStack.push(existingDirectory.getName());
            File next = existingDirectory.getParentFile();
            if (next == null) {
                break;
            }
            existingDirectory = next;
        }

        FileUtils.forceMkdir(directory.toFile());

        while (!pathStack.isEmpty()) {
            try {
                String nextDirectory = pathStack.pop();
                Files.setPosixFilePermissions(Paths.get(existingDirectory.getAbsolutePath(), nextDirectory), PosixFilePermissions.fromString(permissions));
                existingDirectory = new File(existingDirectory, nextDirectory);
            } catch (Exception e) {
            }
        }
        return true;
    }

    public static InputStream getResourceStreamFromAgentJar(String resourceName) {
        try {
            return new URL("jar:" + Agent.getAgentJarURL().toExternalForm() + "!/" + resourceName).openStream();
        } catch (Exception e) {
            logger.log(LogLevel.SEVERE, String.format("Unable to locate resource from agent jar : %s", e.getMessage()), CommonUtils.class.getName());
            logger.log(LogLevel.FINER, "Unable to locate resource from agent jar : ", e, CommonUtils.class.getName());
        }
        return null;
    }


    /**
     * Generate random int between range start to end. Both inclusive.
     * @param start lower bound
     * @param end upper bound
     * @return random int
     */
    public static int generateSecureRandomBetween(int start, int end) {
        return secureRandom.nextInt(end-start) + start;
    }
}
