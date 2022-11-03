package com.k2cybersecurity.intcodeagent.schedulers;

import com.k2cybersecurity.instrumentator.K2Instrumentator;
import com.k2cybersecurity.instrumentator.httpclient.HttpClient;
import com.k2cybersecurity.instrumentator.httpclient.IRestClientConstants;
import com.k2cybersecurity.instrumentator.os.OSVariables;
import com.k2cybersecurity.instrumentator.os.OsVariablesInstance;
import com.k2cybersecurity.instrumentator.utils.AgentUtils;
import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import com.k2cybersecurity.intcodeagent.filelogging.LogLevel;
import com.k2cybersecurity.intcodeagent.logging.IAgentConstants;
import com.k2cybersecurity.intcodeagent.models.config.AgentPolicy;
import com.k2cybersecurity.intcodeagent.utils.CommonUtils;
import com.k2cybersecurity.intcodeagent.websocket.EventSendPool;
import okhttp3.Response;
import org.apache.commons.lang3.StringUtils;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.*;

// TODO: Need to revisit since task cancellation is not implemented.
public class PolicyPullST {

    private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

    final private static Object lock = new Object();
    public static final String POLICY_WRITE_FAILED = "policy write failed : ";
    public static final String POLICY_READ_FAILED_S_S = "Policy read failed : %s : %s";
    public static final String POLICY_READ_FAILED = "Policy read failed !!! ";
    public static final String FALLING_BACK_TO_DEFAULT_CONFIG = "Falling back to current config.";
    public static final String FALLING_BACK_TO_DEFAULT_CONFIG_MSG = "Falling back to current config due to %s";
    public static final String POLICY_WRITTEN_TO_FILE = "policy written to file : ";
    public static final String SHUTTING_POLICY_PULL = "Shutting policy pull!!!";
    public static final String CANCEL_CURRENT_TASK_OF_POLICY_PULL = "Cancel current task of policy pull.";
    public static final String THE_POLICY_FILE_IS_NOT_PRESENT_ON_LOCATION_CREATING_NEW = "The policy file is not present on location creating new!!!";
    public static final String DEFAULT_POLICY_YAML = "default-policy.yaml";
    public static final String GROUP_NAME = "group";
    public static final String APPLICATION_UUID = "applicationUUID";

    private ScheduledExecutorService executorService;

    private ScheduledFuture future;

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

        future = executorService.schedule(runnable, 0, TimeUnit.SECONDS);
        logger.log(LogLevel.INFO, "policy fetch schedule thread started successfully!!!", PolicyPullST.class.getName());
    }

    private Runnable runnable = new Runnable() {
        @Override
        public void run() {
            try {
                task();
            } finally {
                if (AgentUtils.getInstance().getAgentPolicy().getPolicyPull() && AgentUtils.getInstance().getAgentPolicy().getPolicyPullInterval() > 0) {
                    future = executorService.schedule(runnable, AgentUtils.getInstance().getAgentPolicy().getPolicyPullInterval(), TimeUnit.SECONDS);
                }
            }
        }
    };

    public void submitNewTask() {
        if (cancelTask(false) && AgentUtils.getInstance().getAgentPolicy().getPolicyPull() && AgentUtils.getInstance().getAgentPolicy().getPolicyPullInterval() > 0) {
            future = executorService.schedule(runnable, 0, TimeUnit.SECONDS);
        }
    }


    /**
     * On startup, Instantiating collector policy with default values.
     */
    public static void instantiateDefaultPolicy() {
        logger.log(LogLevel.INFO, "Instantiating collector policy with default!!!", PolicyPullST.class.getName());
//        FileUtils.deleteQuietly(AgentUtils.getInstance().getConfigLoadPath());
        if (readAndApplyConfig(new AgentPolicy())) {
            AgentUtils.getInstance().enforcePolicy();
        }
//        CommonUtils.writePolicyToFile();
//        DirectoryWatcher.watchDirectories(Collections.singletonList(AgentUtils.getInstance().getConfigLoadPath().getParent()), false);
    }

    private void task() {
        try {
            AgentPolicy newPolicy;

            Map<String, String> queryParam = new HashMap<>();
            queryParam.put(GROUP_NAME, AgentUtils.getInstance().getGroupName());
            queryParam.put(APPLICATION_UUID, K2Instrumentator.APPLICATION_UUID);
            Response response = HttpClient.getInstance().doGet(IRestClientConstants.GET_POLICY, null, queryParam, null, false);
            if (response.isSuccessful()) {
                newPolicy = HttpClient.getInstance().readResponse(response.body().byteStream(), AgentPolicy.class);
            } else if (response != null && response.body() != null) {
                logger.log(LogLevel.ERROR, String.format(IAgentConstants.UNABLE_TO_PARSE_AGENT_POLICY_DUE_TO_ERROR, response.code(), response.body().string()), PolicyPullST.class.getName());
                logger.postLogMessageIfNecessary(LogLevel.ERROR, String.format(IAgentConstants.UNABLE_TO_PARSE_AGENT_POLICY_DUE_TO_ERROR, response.code(), response.body().string()), null, PolicyPullST.class.getName());
                return;
            } else {
                logger.log(LogLevel.ERROR, IAgentConstants.POLICY_PULL_RESPONSE_IS_NULL, PolicyPullST.class.getName());
                return;
            }

            if (!CommonUtils.validateCollectorPolicySchema(newPolicy)) {
                logger.log(LogLevel.WARN, String.format(IAgentConstants.UNABLE_TO_VALIDATE_AGENT_POLICY_DUE_TO_ERROR, newPolicy), PolicyPullST.class.getName());
                logger.postLogMessageIfNecessary(LogLevel.WARN, String.format(IAgentConstants.UNABLE_TO_VALIDATE_AGENT_POLICY_DUE_TO_ERROR, newPolicy), null, PolicyPullST.class.getName());
                return;
            }

            boolean changed = readAndApplyConfig(newPolicy);
            if (changed) {
//                CommonUtils.writePolicyToFile();
            }
        } catch (Exception e) {
            logger.log(LogLevel.ERROR, POLICY_READ_FAILED, e, PolicyPullST.class.getName());
        }
    }

    public static boolean readAndApplyConfig(AgentPolicy newPolicy) {
        try {
            if (StringUtils.equals(newPolicy.getVersion(), AgentUtils.getInstance().getAgentPolicy().getVersion())) {
                return false;
            }
            logger.logInit(LogLevel.INFO,
                    String.format(IAgentConstants.RECEIVED_AGENT_POLICY, newPolicy),
                    PolicyPullST.class.getName());
            AgentUtils.getInstance().setAgentPolicy(newPolicy);
            K2Instrumentator.APPLICATION_INFO_BEAN.setPolicyVersion(AgentUtils.getInstance().getAgentPolicy().getVersion());
            logger.logInit(LogLevel.INFO, String.format(IAgentConstants.AGENT_POLICY_APPLIED_S,
                    AgentUtils.getInstance().getAgentPolicy()), PolicyPullST.class.getName());
            AgentUtils.getInstance().applyNRPolicyOverride();
            AgentUtils.getInstance().setApplicationInfo();
            if (AgentUtils.getInstance().isPolicyOverridden()){
                logger.log(LogLevel.INFO, String.format("NR policy over-ride in place. Updated policy : %s",
                        AgentUtils.getInstance().getAgentPolicy()), PolicyPullST.class.getName());
                AgentUtils.getInstance().getAgentPolicy().setVersion("overridden");
                CommonUtils.fireUpdatePolicyAPI(AgentUtils.getInstance().getAgentPolicy());
            }
            AgentUtils.getInstance().getStatusLogValues().put("policy-version", AgentUtils.getInstance().getAgentPolicy().getVersion());
            EventSendPool.getInstance().sendEvent(K2Instrumentator.APPLICATION_INFO_BEAN.toString());
            return true;
        } catch (Throwable e) {
            logger.logInit(LogLevel.ERROR, IAgentConstants.UNABLE_TO_SET_AGENT_POLICY_DUE_TO_ERROR, e,
                    PolicyPullST.class.getName());
            return false;
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

    public boolean cancelTask(boolean forceCancel) {
        if (future == null) {
            return true;
        }
        if (future != null && (forceCancel || future.isDone() || future.getDelay(TimeUnit.SECONDS) > AgentUtils.getInstance().getAgentPolicy().getPolicyPullInterval())) {
            logger.log(LogLevel.INFO, CANCEL_CURRENT_TASK_OF_POLICY_PULL, PolicyPullST.class.getName());
            future.cancel(true);
            return true;
        }
        return false;
    }

    public static void shutDownPool() {
        if (instance != null) {
            instance.shutDownThreadPoolExecutor();
        }
    }

    /**
     * Shut down the thread pool executor. Calls normal shutdown of thread pool
     * executor and awaits for termination. If not terminated, forcefully shuts down
     * the executor after a timeout.
     */
    public void shutDownThreadPoolExecutor() {

        if (executorService != null) {
            try {
                executorService.shutdown(); // disable new tasks from being submitted
                if (!executorService.awaitTermination(1, TimeUnit.SECONDS)) {
                    // wait for termination for a timeout
                    executorService.shutdownNow(); // cancel currently executing tasks

                    if (!executorService.awaitTermination(1, TimeUnit.SECONDS)) {
                        logger.log(LogLevel.FATAL, "Thread pool executor did not terminate",
                                PolicyPullST.class.getName());
                    } else {
                        logger.log(LogLevel.INFO, "Thread pool executor terminated",
                                PolicyPullST.class.getName());
                    }
                }
            } catch (InterruptedException e) {
            }
        }
    }
}
