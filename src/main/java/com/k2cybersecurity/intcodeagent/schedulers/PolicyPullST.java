package com.k2cybersecurity.intcodeagent.schedulers;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import com.fasterxml.jackson.dataformat.yaml.YAMLGenerator;
import com.k2cybersecurity.instrumentator.K2Instrumentator;
import com.k2cybersecurity.instrumentator.httpclient.HttpClient;
import com.k2cybersecurity.instrumentator.httpclient.IRestClientConstants;
import com.k2cybersecurity.instrumentator.os.OSVariables;
import com.k2cybersecurity.instrumentator.os.OsVariablesInstance;
import com.k2cybersecurity.instrumentator.utils.AgentUtils;
import com.k2cybersecurity.instrumentator.utils.DirectoryWatcher;
import com.k2cybersecurity.intcodeagent.controlcommand.ControlCommandProcessor;
import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import com.k2cybersecurity.intcodeagent.filelogging.LogLevel;
import com.k2cybersecurity.intcodeagent.logging.IAgentConstants;
import com.k2cybersecurity.intcodeagent.models.config.AgentPolicy;
import com.squareup.okhttp.Response;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;

import java.io.IOException;
import java.io.InputStream;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.*;

public class PolicyPullST {

    private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

    final private static Object lock = new Object();
    public static final String POLICY_WRITE_FAILED = "policy write failed : ";
    public static final String POLICY_READ_FAILED_S_S = "Policy read failed : %s : %s";
    public static final String POLICY_READ_FAILED = "Policy read failed !!! ";
    public static final String FALLING_BACK_TO_DEFAULT_CONFIG = "Falling back to default config.";

    private ScheduledExecutorService executorService;

    private Future future;

    private Map<String, String> queryParam = new HashMap<>();

    private static PolicyPullST instance;

    private OSVariables osVariables = OsVariablesInstance.getInstance().getOsVariables();

    private PolicyPullST() {
        logger.log(LogLevel.INFO, "policy pull for group name: " + AgentUtils.getInstance().getGroupName(), PolicyPullST.class.getName());
        executorService = Executors.newSingleThreadScheduledExecutor(new ThreadFactory() {
            @Override
            public Thread newThread(Runnable r) {
                return new Thread(Thread.currentThread().getThreadGroup(), r,
                        "K2-pull-policy-st");
            }
        });

        queryParam.put("group", AgentUtils.getInstance().getGroupName());
        queryParam.put("applicationUUID", K2Instrumentator.APPLICATION_UUID);
        logger.log(LogLevel.INFO, " Query param created : " + queryParam, PolicyPullST.class.getName());
        executorService.schedule(runnable, 0, TimeUnit.MINUTES);
        logger.log(LogLevel.INFO, "policy fetch schedule thread started successfully!!!", PolicyPullST.class.getName());
    }

    private Runnable runnable = new Runnable() {
        @Override
        public void run() {
            try {
                task();
            } finally {
                if (AgentUtils.getInstance().getAgentPolicy().getPolicyPull() && AgentUtils.getInstance().getAgentPolicy().getPolicyPullInterval() > 0) {
                    future = executorService.schedule(runnable, AgentUtils.getInstance().getAgentPolicy().getPolicyPullInterval(), TimeUnit.MINUTES);
                }
            }
        }
    };

    private void task() {
        try {
            logger.log(LogLevel.INFO, " Query param found : " + queryParam, PolicyPullST.class.getName());
            Response response = HttpClient.getInstance().doGet(IRestClientConstants.GET_POLICY, null, queryParam, null, false);
            if (response.isSuccessful()) {
                AgentPolicy newPolicy = HttpClient.getInstance().readResponse(response.body().byteStream(), AgentPolicy.class);
                readAndApplyConfig(newPolicy);
                writePolicyToFile();
            } else {
                logger.log(LogLevel.ERROR, String.format(POLICY_READ_FAILED_S_S, response.code(), response.body().string()), PolicyPullST.class.getName());
            }
        } catch (Exception e) {
            logger.log(LogLevel.ERROR, POLICY_READ_FAILED, e, PolicyPullST.class.getName());
        }
    }

    public void readAndApplyConfig(AgentPolicy newPolicy) {
        try {
            if (StringUtils.equals(newPolicy.getVersion(), AgentUtils.getInstance().getAgentPolicy().getVersion())) {
                return;
            }
            AgentUtils.getInstance().setAgentPolicy(newPolicy);
            AgentUtils.getInstance().enforcePolicy();
            logger.log(LogLevel.INFO, String.format(IAgentConstants.AGENT_POLICY_APPLIED_S,
                    AgentUtils.getInstance().getAgentPolicy()), ControlCommandProcessor.class.getName());
        } catch (Throwable e) {
            logger.log(LogLevel.ERROR, IAgentConstants.UNABLE_TO_SET_AGENT_POLICY_DUE_TO_ERROR, e,
                    ControlCommandProcessor.class.getName());
        }
    }

    private void writePolicyToFile() {
        try {
            ObjectMapper mapper = new ObjectMapper(new YAMLFactory().disable(YAMLGenerator.Feature.WRITE_DOC_START_MARKER));
            FileUtils.touch(AgentUtils.getInstance().getConfigLoadPath());
            mapper.writeValue(AgentUtils.getInstance().getConfigLoadPath(), AgentUtils.getInstance().getAgentPolicy());
            DirectoryWatcher.watchDirectories(Collections.singletonList(AgentUtils.getInstance().getConfigLoadPath().getParent()), false);
        } catch (IOException e) {
            logger.log(LogLevel.ERROR, POLICY_WRITE_FAILED, e, PolicyPullST.class.getName());
        }
    }

    public static PolicyPullST getInstance() {
        if (instance == null) {
            synchronized (lock) {
                if (instance == null) {
                    instance = new PolicyPullST();
                }
            }
        }
        return instance;
    }

    public void cancelTask() {
        if (future != null) {
            future.cancel(false);
        }
    }

    public AgentPolicy populateConfig() {
        if (!AgentUtils.getInstance().getConfigLoadPath().isFile()) {
            return loadDefaultConfig();
        }
        ObjectMapper mapper = new ObjectMapper(new YAMLFactory());
        try {
            AgentUtils.getInstance()
                    .setAgentPolicy(mapper.readValue(AgentUtils.getInstance().getConfigLoadPath(), AgentPolicy.class));
            return AgentUtils.getInstance().getAgentPolicy();
        } catch (Exception e) {
            logger.log(LogLevel.ERROR, FALLING_BACK_TO_DEFAULT_CONFIG, e, DirectoryWatcher.class.getName());
            return loadDefaultConfig();
        }
    }

    private AgentPolicy loadDefaultConfig() {
        try {
            InputStream in = this.getClass().getClassLoader().getResourceAsStream("default-policy.yaml");
            ObjectMapper mapper = new ObjectMapper(new YAMLFactory());
            return mapper.readValue(in, AgentPolicy.class);
        } catch (Exception e) {
            logger.log(LogLevel.ERROR, FALLING_BACK_TO_DEFAULT_CONFIG, e, DirectoryWatcher.class.getName());
            return null;
        }
    }
}
