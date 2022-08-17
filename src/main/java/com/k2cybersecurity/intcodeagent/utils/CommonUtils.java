package com.k2cybersecurity.intcodeagent.utils;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import com.fasterxml.jackson.dataformat.yaml.YAMLGenerator;
import com.k2cybersecurity.instrumentator.K2Instrumentator;
import com.k2cybersecurity.instrumentator.httpclient.HttpClient;
import com.k2cybersecurity.instrumentator.httpclient.IRestClientConstants;
import com.k2cybersecurity.instrumentator.utils.AgentUtils;
import com.k2cybersecurity.instrumentator.utils.DirectoryWatcher;
import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import com.k2cybersecurity.intcodeagent.filelogging.LogLevel;
import com.k2cybersecurity.intcodeagent.models.config.AgentPolicy;
import com.k2cybersecurity.intcodeagent.models.config.AgentPolicyParameters;
import com.k2cybersecurity.intcodeagent.schedulers.PolicyPullST;
import com.networknt.schema.JsonSchema;
import com.networknt.schema.JsonSchemaFactory;
import com.networknt.schema.SpecVersion;
import com.networknt.schema.ValidationMessage;
import org.apache.commons.io.FileUtils;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.Stack;

public class CommonUtils {

    private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();
    public static final String POLICY_WRITE_FAILED = "policy write failed : ";
    public static final String POLICY_WRITTEN_TO_FILE = "policy written to file : ";
    public static JsonSchemaFactory factory = JsonSchemaFactory.getInstance(SpecVersion.VersionFlag.V4);
    public static JsonSchema lcPolicyParamSchema = factory.getSchema(CommonUtils.class.getClassLoader().getSystemResourceAsStream("lc-policy-parameters-schema.json"));
    public static JsonSchema lcPolicySchema = factory.getSchema(CommonUtils.class.getClassLoader().getSystemResourceAsStream("lc-policy-schema.json"));

    static {
        lcPolicySchema.initializeValidators();
        lcPolicyParamSchema.initializeValidators();
    }

    public static boolean validateCollectorPolicyParameterSchema(AgentPolicyParameters policyParameters) {
        try {
            Set<ValidationMessage> errors = lcPolicyParamSchema.validate(new ObjectMapper().readTree(policyParameters.toString()));
            if (errors.isEmpty()) {
                return true;
            }
            logger.log(LogLevel.ERROR, String.format("LC Policy Parameters validation failed due to following violations: %s", errors), CommonUtils.class.getName());
            return false;
        } catch (Exception e) {
            logger.log(LogLevel.ERROR, String.format("Exception raised in LC policy Parameters validation : %s :: caused by : %s", e.getMessage(), e.getCause()), CommonUtils.class.getName());
            logger.log(LogLevel.DEBUG, "Exception raised in LC policy Parameters validation", e, CommonUtils.class.getName());
        }
        return false;
    }

//    public static boolean validateCollectorPolicyParameterSchema(AgentPolicyParameters policyParameters) {
//
//        try {
//            JSONObject jsonSchema = new JSONObject(
//                    new JSONTokener(CommonUtils.class.getClassLoader().getSystemResourceAsStream("lc-policy-parameters-schema.json")));
//            JSONObject jsonSubject = new JSONObject(
//                    new JSONTokener(policyParameters.toString()));
//
//            Schema schema = SchemaLoader.load(jsonSchema);
//            schema.validate(jsonSubject);
//            return true;
//        } catch (ValidationException e) {
//            logger.log(LogLevel.ERROR, String.format("LC Policy Parameters validation failed due to following violations: %s", e.getAllMessages()), CommonUtils.class.getName());
//            logger.log(LogLevel.DEBUG, "LC Policy Parameters validation failed due to", e, CommonUtils.class.getName());
//        } catch (Exception e) {
//            logger.log(LogLevel.ERROR, String.format("Exception raised in LC policy Parameters validation : %s :: caused by : %s", e.getMessage(), e.getCause()), CommonUtils.class.getName());
//            logger.log(LogLevel.DEBUG, "Exception raised in LC policy Parameters validation", e, CommonUtils.class.getName());
//        }
//        return false;
//    }

    public static boolean validateCollectorPolicySchema(AgentPolicy policy) {

        try {
            Set<ValidationMessage> errors = lcPolicySchema.validate(new ObjectMapper().readTree(policy.toString()));
            if (errors.isEmpty()) {
                return true;
            }
            logger.log(LogLevel.ERROR, String.format("LC Policy Parameters validation failed due to following violations: %s", errors), CommonUtils.class.getName());
            return false;
        } catch (Exception e) {
            logger.log(LogLevel.ERROR, String.format("Exception raised in LC policy validation : %s :: caused by : %s", e.getMessage(), e.getCause()), CommonUtils.class.getName());
            logger.log(LogLevel.DEBUG, "Exception raised in LC policy validation", e, CommonUtils.class.getName());
        }
        return false;
    }

    public static void fireUpdatePolicyAPI(AgentPolicy policy) {
        try {
            Map<String, String> queryParam = new HashMap<>();
            queryParam.put("group", AgentUtils.getInstance().getGroupName());
            queryParam.put("applicationUUID", K2Instrumentator.APPLICATION_UUID);

            HttpClient.getInstance().doPost(IRestClientConstants.UPDATE_POLICY, null, queryParam, null, policy, true);
        } catch (Exception e) {
            logger.log(LogLevel.WARN, String.format("Update policy to IC failed due to %s", e.getMessage()), DirectoryWatcher.class.getName());
        }
    }

    public static void writePolicyToFile() {
        try {
            ObjectMapper mapper = new ObjectMapper(new YAMLFactory().disable(YAMLGenerator.Feature.WRITE_DOC_START_MARKER));
            CommonUtils.forceMkdirs(AgentUtils.getInstance().getConfigLoadPath().getParentFile().toPath(), "rwxrwxrwx");
            FileUtils.touch(AgentUtils.getInstance().getConfigLoadPath());
            try {
                AgentUtils.getInstance().getConfigLoadPath().setReadable(true, false);
                AgentUtils.getInstance().getConfigLoadPath().setWritable(true, false);
            } catch (Exception e) {
            }
            mapper.writeValue(AgentUtils.getInstance().getConfigLoadPath(), AgentUtils.getInstance().getAgentPolicy());
            logger.log(LogLevel.INFO, POLICY_WRITTEN_TO_FILE + AgentUtils.getInstance().getConfigLoadPath(), PolicyPullST.class.getName());
        } catch (Exception e) {
            logger.log(LogLevel.ERROR, POLICY_WRITE_FAILED, e, PolicyPullST.class.getName());
        }
    }

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
}
