package com.newrelic.agent.security.intcodeagent.utils;

import com.newrelic.agent.security.AgentInfo;
import com.newrelic.agent.security.instrumentator.httpclient.HttpClient;
import com.newrelic.agent.security.instrumentator.httpclient.IRestClientConstants;
import com.newrelic.agent.security.instrumentator.utils.AgentUtils;
import com.newrelic.agent.security.intcodeagent.filelogging.FileLoggerThreadPool;
import com.newrelic.agent.security.intcodeagent.filelogging.LogLevel;
import com.newrelic.agent.security.intcodeagent.models.config.AgentPolicyParameters;
import com.newrelic.agent.security.intcodeagent.models.javaagent.LogMessage;
import com.newrelic.api.agent.security.schema.policy.AgentPolicy;
import com.newrelic.api.agent.NewRelic;
import org.apache.commons.io.FileUtils;
import org.everit.json.schema.Schema;
import org.everit.json.schema.ValidationException;
import org.everit.json.schema.loader.SchemaLoader;
import org.json.JSONObject;
import org.json.JSONTokener;

import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLClassLoader;
import java.net.URLDecoder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.HashMap;
import java.util.Map;
import java.util.Stack;
import java.util.jar.JarFile;
import java.util.zip.ZipEntry;

public class CommonUtils {

    private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();
    public static final String POLICY_WRITE_FAILED = "policy write failed : ";
    public static final String POLICY_WRITTEN_TO_FILE = "policy written to file : ";

    public static boolean validateCollectorPolicyParameterSchema(AgentPolicyParameters policyParameters) {

        try {
            JSONObject jsonSchema = new JSONObject(
                    new JSONTokener(CommonUtils.class.getClassLoader().getSystemResourceAsStream("lc-policy-parameters-schema.json")));
            JSONObject jsonSubject = new JSONObject(
                    new JSONTokener(policyParameters.toString()));

            Schema schema = SchemaLoader.load(jsonSchema);
            schema.validate(jsonSubject);
            return true;
        } catch (ValidationException e) {
            logger.log(LogLevel.ERROR, String.format("LC Policy Parameters validation failed due to following violations: %s", e.getAllMessages()), CommonUtils.class.getName());
            logger.log(LogLevel.DEBUG, "LC Policy Parameters validation failed due to", e, CommonUtils.class.getName());
            logger.postLogMessageIfNecessary(LogLevel.ERROR, String.format("LC Policy Parameters validation failed due to following violations: %s", e.getAllMessages()), e, CommonUtils.class.getName());
        } catch (Exception e) {
            logger.log(LogLevel.ERROR, String.format("Exception raised in LC policy Parameters validation : %s :: caused by : %s", e.getMessage(), e.getCause()), CommonUtils.class.getName());
            logger.log(LogLevel.DEBUG, "Exception raised in LC policy Parameters validation", e, CommonUtils.class.getName());
            logger.postLogMessageIfNecessary(LogLevel.ERROR, String.format("Exception raised in LC policy Parameters validation : %s :: caused by : %s", e.getMessage(), e.getCause()), e, CommonUtils.class.getName());

        }
        return false;
    }

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
            logger.postLogMessageIfNecessary(LogLevel.ERROR, String.format("LC Policy validation failed due to following violations: %s", e.getAllMessages()), e, CommonUtils.class.getName());
        } catch (Exception e) {
            logger.log(LogLevel.ERROR, String.format("Exception raised in LC policy validation : %s :: caused by : %s", e.getMessage(), e.getCause()), CommonUtils.class.getName());
            logger.log(LogLevel.DEBUG, "Exception raised in LC policy validation", e, CommonUtils.class.getName());
            logger.postLogMessageIfNecessary(LogLevel.ERROR, String.format("Exception raised in LC policy validation : %s :: caused by : %s", e.getMessage(), e.getCause()), e, CommonUtils.class.getName());
        }
        return false;
    }

    public static void fireUpdatePolicyAPI(AgentPolicy policy) {
        if (policy == null) {
            return;
        }
        try {
            Map<String, String> queryParam = new HashMap<>();
            queryParam.put("group", AgentUtils.getInstance().getGroupName());
            queryParam.put("applicationUUID", AgentInfo.getInstance().getApplicationUUID());

            HttpClient.getInstance().doPost(IRestClientConstants.UPDATE_POLICY, null, queryParam, null, policy, true);
        } catch (Exception e) {
            logger.log(LogLevel.WARN, String.format("Update policy to IC failed due to %s", e.getMessage()), CommonUtils.class.getName());
        }
    }

    public static void fireLogMessageUploadAPI(LogMessage logMessage) {
        if (logMessage == null || !HttpClient.isConnected() || !AgentInfo.getInstance().isAgentActive()) {
            return;
        }
        try {
            HttpClient.getInstance().doPost(IRestClientConstants.POST_LOG_MESSAGE, null, null, null, logMessage, true);
        } catch (Exception e) {
            logger.log(LogLevel.WARN, String.format("Upload log message to IC failed due to %s", e.getMessage()), CommonUtils.class.getName());
        }
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

    public static String getNRAgentJarDirectory() {
        try {
            URL agentJarUrl = getAgentJarUrl();
            if (agentJarUrl != null) {
                File file = new File(getAgentJarFileName(agentJarUrl));
                if (file.exists()) {
                    return file.getParent();
                }
            }
        } catch (Throwable ignored) {
        }
        return null;
    }

    /*
        Below methods are taken from com.newrelic.agent.config.AgentJarHelper
     */
    public static URL getAgentJarUrl() {
        if (System.getProperty("newrelic.agent_jarfile") != null) {
            try {
                return new URL("file://" + System.getProperty("newrelic.agent_jarfile"));
            } catch (MalformedURLException e) {
                logger.log(LogLevel.DEBUG,"Unable to create a valid url from " + System.getProperty("newrelic.agent_jarfile"), e, CommonUtils.class.getName());

            }
        }

        // Use AgentJarHelper's ClassLoader here because this is called from the BootstrapAgent premain
        ClassLoader classLoader = NewRelic.getAgent().getClass().getClassLoader();
        if (classLoader instanceof URLClassLoader) {
            URL[] urls = ((URLClassLoader) classLoader).getURLs();
            for (URL url : urls) {
                if (url.getFile().endsWith("newrelic.jar")) {
                    if (jarFileNameExists(url, "com/newrelic/agent/Agent.class")) {
                        return url;
                    }
                }
            }
            String agentClassName = "com/newrelic/agent/Agent.class".replace('.', '/');
            for (URL url : urls) {
                try (JarFile jarFile = new JarFile(url.getFile())) {
                    ZipEntry entry = jarFile.getEntry(agentClassName);
                    if (entry != null) {
                        return url;
                    }
                } catch (IOException e) {
                }
            }
        }
        // technically this is all that is needed to get the jar URL
        // but it does require a new permission so it will be the
        // fallback method for the time being (the above approach
        // frequently fails when using a custom system class loader)
        return NewRelic.getAgent().getClass().getProtectionDomain().getCodeSource().getLocation();
    }

    public static boolean jarFileNameExists(URL agentJarUrl, String name) {
        try (JarFile jarFile = getAgentJarFile(agentJarUrl)) {
            return jarFile.getEntry(name) != null;
        } catch (Exception e) {
            logger.log(LogLevel.DEBUG,"Unable to search the agent jar for " + name, e, CommonUtils.class.getName());
        }
        return false;
    }

    private static JarFile getAgentJarFile(URL agentJarUrl) {
        if (agentJarUrl == null) {
            return null;
        }
        try {
            return new JarFile(getAgentJarFileName(agentJarUrl));
        } catch (IOException e) {
            return null;
        }
    }

    private static String getAgentJarFileName(URL agentJarUrl) {
        if (agentJarUrl == null) {
            return null;
        }
        try {
            return URLDecoder.decode(agentJarUrl.getFile().replace("+", "%2B"), "UTF-8");
        } catch (IOException e) {
            return null;
        }
    }
}
