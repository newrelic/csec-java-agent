package com.newrelic.agent.security.intcodeagent.utils;

import org.apache.commons.io.FileUtils;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.SecureRandom;
import java.util.Stack;

public class CommonUtils {
    /**
     * This class can't have a logger
     */

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
