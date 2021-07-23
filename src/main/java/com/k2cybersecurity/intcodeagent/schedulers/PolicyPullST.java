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
import com.k2cybersecurity.intcodeagent.controlcommand.ControlCommandProcessor;
import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import com.k2cybersecurity.intcodeagent.filelogging.LogLevel;
import com.k2cybersecurity.intcodeagent.logging.IAgentConstants;
import com.k2cybersecurity.intcodeagent.models.config.AgentPolicy;
import com.squareup.okhttp.Response;
import org.apache.commons.lang3.StringUtils;

import java.io.File;
import java.io.IOException;
import java.util.Map;
import java.util.concurrent.*;

public class PolicyPullST {

    private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

    final private static Object lock = new Object();
    public static final String POLICY_WRITE_FAILED = "policy write failed : ";
    public static final String POLICY_READ_FAILED_S_S = "Policy read failed : %s : %s";
    public static final String POLICY_READ_FAILED = "Policy read failed !!! ";

    private ScheduledExecutorService executorService;

    private Future future;

    private Map<String, String> queryParam;

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
        executorService.schedule(runnable, 0, TimeUnit.MINUTES);
        queryParam.put("group", AgentUtils.getInstance().getGroupName());
        queryParam.put("applicationUUID", K2Instrumentator.APPLICATION_UUID);
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

    private void readAndApplyConfig(AgentPolicy newPolicy) {
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
            mapper.writeValue(new File(osVariables.getConfigPath(), String.format("policy-%s.yaml", K2Instrumentator.APPLICATION_UUID)), AgentUtils.getInstance().getAgentPolicy());

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
}
