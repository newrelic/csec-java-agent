package com.k2cybersecurity.intcodeagent.utils;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import com.fasterxml.jackson.dataformat.yaml.YAMLGenerator;
import com.k2cybersecurity.instrumentator.utils.AgentUtils;
import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import com.k2cybersecurity.intcodeagent.filelogging.LogLevel;
import com.k2cybersecurity.intcodeagent.models.config.AgentPolicy;
import com.k2cybersecurity.intcodeagent.schedulers.PolicyPullST;
import org.apache.commons.io.FileUtils;
import org.everit.json.schema.Schema;
import org.everit.json.schema.ValidationException;
import org.everit.json.schema.loader.SchemaLoader;
import org.json.JSONObject;
import org.json.JSONTokener;

import java.io.IOException;

public class CommonUtils {

    private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();
    public static final String POLICY_WRITE_FAILED = "policy write failed : ";
    public static final String POLICY_WRITTEN_TO_FILE = "policy written to file : ";

    public static boolean validateCollectorPolicySchema(AgentPolicy policy) {

        try {
            JSONObject jsonSchema = new JSONObject(
                    new JSONTokener(CommonUtils.class.getClassLoader().getSystemResourceAsStream("lc-policy-schema.json")));
            JSONObject jsonSubject = new JSONObject(
                    new JSONTokener(policy.toString()));

            Schema schema = SchemaLoader.load(jsonSchema);
            schema.validate(jsonSubject);
            return true;
        } catch (ValidationException e) {
            logger.log(LogLevel.ERROR, String.format("LC Policy validation failed due to following violations: %s", e.getAllMessages()), CommonUtils.class.getName());
            logger.log(LogLevel.DEBUG, "LC Policy validation failed due to", e, CommonUtils.class.getName());
        } catch (Exception e) {
            logger.log(LogLevel.ERROR, String.format("Exception raised in LC policy validation : %s :: caused by : %s", e.getMessage(), e.getCause()), CommonUtils.class.getName());
            logger.log(LogLevel.DEBUG, "Exception raised in LC policy validation", e, CommonUtils.class.getName());
        }
        return false;
    }

    public static void writePolicyToFile() {
        try {
            ObjectMapper mapper = new ObjectMapper(new YAMLFactory().disable(YAMLGenerator.Feature.WRITE_DOC_START_MARKER));
            FileUtils.touch(AgentUtils.getInstance().getConfigLoadPath());
            try {
                AgentUtils.getInstance().getConfigLoadPath().setReadable(true, false);
                AgentUtils.getInstance().getConfigLoadPath().setWritable(true, false);
            } catch (Exception e) {
            }
            mapper.writeValue(AgentUtils.getInstance().getConfigLoadPath(), AgentUtils.getInstance().getAgentPolicy());
            logger.log(LogLevel.DEBUG, POLICY_WRITTEN_TO_FILE + AgentUtils.getInstance().getConfigLoadPath(), PolicyPullST.class.getName());
        } catch (IOException e) {
            logger.log(LogLevel.ERROR, POLICY_WRITE_FAILED, e, PolicyPullST.class.getName());
        }
    }
}
