package com.newrelic.agent.security.intcodeagent.utils;

import com.newrelic.agent.security.instrumentator.os.OsVariablesInstance;
import com.newrelic.agent.security.intcodeagent.filelogging.FileLoggerThreadPool;
import com.newrelic.agent.security.intcodeagent.filelogging.LogLevel;
import com.newrelic.agent.security.intcodeagent.models.config.AgentPolicyParameters;
import com.newrelic.agent.security.intcodeagent.websocket.JsonConverter;
import com.newrelic.api.agent.security.Agent;
import com.newrelic.api.agent.security.schema.policy.AgentPolicy;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.comparator.LastModifiedFileComparator;
import org.apache.commons.io.filefilter.FileFilterUtils;
import org.everit.json.schema.Schema;
import org.everit.json.schema.ValidationException;
import org.everit.json.schema.loader.SchemaLoader;
import org.json.JSONObject;
import org.json.JSONTokener;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Collection;
import java.util.Stack;

public class CommonUtils {

    private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();
    public static final String POLICY_WRITE_FAILED = "policy write failed : ";
    public static final String POLICY_WRITTEN_TO_FILE = "policy written to file : ";

    public static SecureRandom secureRandom = new SecureRandom();

    public static boolean validateCollectorPolicyParameterSchema(AgentPolicyParameters policyParameters) {

        try {
            JSONObject jsonSchema = new JSONObject(
                    new JSONTokener(getResourceStreamFromAgentJar("lc-policy-parameters-schema.json")));
            JSONObject jsonSubject = new JSONObject(
                    new JSONTokener(JsonConverter.toJSON(policyParameters)));

            Schema schema = SchemaLoader.load(jsonSchema);
            schema.validate(jsonSubject);
            return true;
        } catch (ValidationException e) {
            logger.log(LogLevel.SEVERE, String.format("LC Policy Parameters validation failed due to following violations: %s", e.getAllMessages()), CommonUtils.class.getName());
            logger.log(LogLevel.FINER, "LC Policy Parameters validation failed due to", e, CommonUtils.class.getName());
            logger.postLogMessageIfNecessary(LogLevel.SEVERE, String.format("LC Policy Parameters validation failed due to following violations: %s", e.getAllMessages()), e, CommonUtils.class.getName());
        } catch (Exception e) {
            logger.log(LogLevel.SEVERE, String.format("Exception raised in LC policy Parameters validation : %s :: caused by : %s", e.getMessage(), e.getCause()), CommonUtils.class.getName());
            logger.log(LogLevel.FINER, "Exception raised in LC policy Parameters validation", e, CommonUtils.class.getName());
            logger.postLogMessageIfNecessary(LogLevel.SEVERE, String.format("Exception raised in LC policy Parameters validation : %s :: caused by : %s", e.getMessage(), e.getCause()), e, CommonUtils.class.getName());

        }
        return false;
    }

    public static boolean validateCollectorPolicySchema(AgentPolicy policy) {

        try {
            JSONObject jsonSchema = new JSONObject(
                    new JSONTokener(getResourceStreamFromAgentJar("lc-policy-schema.json")));
            JSONObject jsonSubject = new JSONObject(
                    new JSONTokener(JsonConverter.toJSON(policy)));

            Schema schema = SchemaLoader.load(jsonSchema);
            schema.validate(jsonSubject);
            return true;
        } catch (ValidationException e) {
            logger.log(LogLevel.SEVERE, String.format("LC Policy validation failed due to following violations: %s", e.getAllMessages()), CommonUtils.class.getName());
            logger.log(LogLevel.FINER, "LC Policy validation failed due to", e, CommonUtils.class.getName());
            logger.postLogMessageIfNecessary(LogLevel.SEVERE, String.format("LC Policy validation failed due to following violations: %s", e.getAllMessages()), e, CommonUtils.class.getName());
        } catch (Exception e) {
            logger.log(LogLevel.SEVERE, String.format("Exception raised in LC policy validation : %s :: caused by : %s", e.getMessage(), e.getCause()), CommonUtils.class.getName());
            logger.log(LogLevel.FINER, "Exception raised in LC policy validation", e, CommonUtils.class.getName());
            logger.postLogMessageIfNecessary(LogLevel.SEVERE, String.format("Exception raised in LC policy validation : %s :: caused by : %s", e.getMessage(), e.getCause()), e, CommonUtils.class.getName());
        }
        return false;
    }

//    public static void writePolicyToFile() {
//        try {
//            ObjectMapper mapper = new ObjectMapper(new YAMLFactory().disable(YAMLGenerator.Feature.WRITE_DOC_START_MARKER));
//            CommonUtils.forceMkdirs(AgentUtils.getInstance().getConfigLoadPath().getParentFile().toPath(), "rwxrwxrwx");
//            FileUtils.touch(AgentUtils.getInstance().getConfigLoadPath());
//            try {
//                AgentUtils.getInstance().getConfigLoadPath().setReadable(true, false);
//                AgentUtils.getInstance().getConfigLoadPath().setWritable(true, false);
//            } catch (Exception e) {
//            }
//            mapper.writeValue(AgentUtils.getInstance().getConfigLoadPath(), AgentUtils.getInstance().getAgentPolicy());
//            logger.log(LogLevel.INFO, POLICY_WRITTEN_TO_FILE + AgentUtils.getInstance().getConfigLoadPath(), CommonUtils.class.getName());
//        } catch (Exception e) {
//            logger.log(LogLevel.ERROR, POLICY_WRITE_FAILED, e, CommonUtils.class.getName());
//        }
//    }

    public static Boolean forceMkdirs(Path directory, String permissions) {
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

        try {
            FileUtils.forceMkdir(directory.toFile());
        } catch (IOException e) {
            return false;
        }

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
