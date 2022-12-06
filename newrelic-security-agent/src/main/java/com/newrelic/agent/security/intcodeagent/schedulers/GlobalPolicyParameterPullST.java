package com.newrelic.agent.security.intcodeagent.schedulers;

import com.newrelic.agent.security.instrumentator.httpclient.HttpClient;
import com.newrelic.agent.security.instrumentator.httpclient.IRestClientConstants;
import com.newrelic.agent.security.instrumentator.utils.AgentUtils;
import com.newrelic.agent.security.intcodeagent.filelogging.FileLoggerThreadPool;
import com.newrelic.agent.security.intcodeagent.filelogging.LogLevel;
import com.newrelic.agent.security.intcodeagent.logging.IAgentConstants;
import com.newrelic.agent.security.intcodeagent.models.config.AgentPolicyParameters;
import com.newrelic.agent.security.intcodeagent.utils.CommonUtils;
import okhttp3.Response;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.*;

public class GlobalPolicyParameterPullST {

    private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

    final private static Object lock = new Object();
    public static final String VERSION = "version";
    public static final String CANCEL_CURRENT_TASK_OF_GLOBAL_POLICY_PULL = "Cancel current task of global policy pull.";
    public static final String CURRENT_VERSION = "currentVersion";

    private ScheduledExecutorService executorService;

    public static GlobalPolicyParameterPullST instance;

    private ScheduledFuture future;

    public static GlobalPolicyParameterPullST getInstance() {
        if (AgentUtils.getInstance().isStandaloneMode() && instance == null) {
            synchronized (lock) {
                if (instance == null) {
                    instance = new GlobalPolicyParameterPullST();
                }
            }
        }
        return instance;
    }

    public static GlobalPolicyParameterPullST reinstantiate() {
        instance = new GlobalPolicyParameterPullST();
        return instance;
    }

    private GlobalPolicyParameterPullST() {
        logger.log(LogLevel.INFO, "policy pull parameters for group name: " + AgentUtils.getInstance().getGroupName(), GlobalPolicyParameterPullST.class.getName());
        executorService = Executors.newSingleThreadScheduledExecutor(new ThreadFactory() {
            @Override
            public Thread newThread(Runnable r) {
                return new Thread(Thread.currentThread().getThreadGroup(), r,
                        "K2-policy-param-st");
            }
        });
        future = executorService.schedule(runnable, 1, TimeUnit.MINUTES);
        logger.log(LogLevel.INFO, "policy fetch schedule thread started successfully!!!", GlobalPolicyParameterPullST.class.getName());
    }

    Runnable runnable = new Runnable() {
        @Override
        public void run() {
            try {
                AgentPolicyParameters parameters = getPolicyParamters(AgentUtils.getInstance().getAgentPolicyParameters().getVersion());
                if (parameters == null) {
                    return;
                }
                if (!CommonUtils.validateCollectorPolicyParameterSchema(parameters)) {
                    logger.log(LogLevel.WARN, String.format(IAgentConstants.UNABLE_TO_VALIDATE_AGENT_POLICY_PARAMETER_DUE_TO_ERROR, parameters), GlobalPolicyParameterPullST.class.getName());
                    return;
                }
                AgentUtils.getInstance().setAgentPolicyParameters(parameters);
            } finally {
                if (AgentUtils.getInstance().getAgentPolicyParameters().getPolicyPullInterval() > 0) {
                    future = executorService.schedule(runnable, AgentUtils.getInstance().getAgentPolicyParameters().getPolicyPullInterval(), TimeUnit.MINUTES);
                }
            }
        }
    };

    private AgentPolicyParameters getPolicyParamters(String version) {
        try {
            Map<String, String> queryParam = new HashMap<>();
            queryParam.put(CURRENT_VERSION, version);
            Response response = HttpClient.getInstance().doGet(IRestClientConstants.POLICY_PARAMETER, null, queryParam, null, false);
            if (response.isSuccessful() && response.code() == 200) {
                AgentPolicyParameters parameters = HttpClient.getInstance().readResponse(response.body().byteStream(), AgentPolicyParameters.class);
                logger.log(LogLevel.INFO, String.format(IAgentConstants.POLICY_VERSION_CHANGED_POLICY_PARAMETER_PULL_REQUIRED_RESPONSE_BODY, response.code(), parameters), GlobalPolicyParameterPullST.class.getName());
                return parameters;
            } else if (response.isSuccessful() && response.code() == 204) {
                logger.log(LogLevel.INFO, String.format(IAgentConstants.POLICY_NO_CHANGE_IN_GLOBAL_POLICY_PARAMETERS_RESPONSE_BODY, response.code(), response.body().string()), GlobalPolicyParameterPullST.class.getName());
            } else {
                logger.log(LogLevel.ERROR, String.format(IAgentConstants.POLICY_GLOBAL_POLICY_PARAMETERS_API_FAILURE_RESPONSE_BODY, response.code(), response.body().string()), GlobalPolicyParameterPullST.class.getName());
                logger.postLogMessageIfNecessary(LogLevel.ERROR, String.format(IAgentConstants.POLICY_GLOBAL_POLICY_PARAMETERS_API_FAILURE_RESPONSE_BODY, response.code(), response.body().string()), null, GlobalPolicyParameterPullST.class.getName());
            }
        } catch (Exception e) {
            logger.log(LogLevel.ERROR, String.format(IAgentConstants.POLICY_PARAMETER_VERSION_CHECK_FAILED_MESSAGE_CAUSE, e.getMessage(), e.getCause()), GlobalPolicyParameterPullST.class.getName());
            logger.postLogMessageIfNecessary(LogLevel.ERROR, String.format(IAgentConstants.POLICY_PARAMETER_VERSION_CHECK_FAILED_MESSAGE_CAUSE, e.getMessage(), e.getCause()), e, GlobalPolicyParameterPullST.class.getName());
        }
        return null;
    }

    public void submitNewTask() {
        if (cancelTask(false) && AgentUtils.getInstance().getAgentPolicyParameters().getPolicyPullInterval() > 0) {
            future = executorService.schedule(runnable, AgentUtils.getInstance().getAgentPolicyParameters().getPolicyPullInterval(), TimeUnit.MINUTES);
        }
    }

    public boolean cancelTask(boolean forceCancel) {
        if (future == null) {
            return true;
        }
        if (future != null && (forceCancel || future.isDone() || future.getDelay(TimeUnit.MINUTES) > AgentUtils.getInstance().getAgentPolicyParameters().getPolicyPullInterval())) {
            logger.log(LogLevel.INFO, CANCEL_CURRENT_TASK_OF_GLOBAL_POLICY_PULL, GlobalPolicyParameterPullST.class.getName());
            future.cancel(true);
            return true;
        }
        return false;
    }

    public static void shutDownPool() {
        if (instance != null) {
            instance.shutDownThreadPoolExecutor();
        }
        instance = null;
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
                                GlobalPolicyParameterPullST.class.getName());
                    } else {
                        logger.log(LogLevel.INFO, "Thread pool executor terminated",
                                GlobalPolicyParameterPullST.class.getName());
                    }
                }
            } catch (InterruptedException e) {
            }
        }
    }
}
