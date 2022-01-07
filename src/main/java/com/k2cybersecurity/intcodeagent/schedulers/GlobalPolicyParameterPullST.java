package com.k2cybersecurity.intcodeagent.schedulers;

import com.k2cybersecurity.instrumentator.K2Instrumentator;
import com.k2cybersecurity.instrumentator.httpclient.HttpClient;
import com.k2cybersecurity.instrumentator.httpclient.IRestClientConstants;
import com.k2cybersecurity.instrumentator.utils.AgentUtils;
import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import com.k2cybersecurity.intcodeagent.filelogging.LogLevel;
import com.k2cybersecurity.intcodeagent.logging.IAgentConstants;
import com.k2cybersecurity.intcodeagent.models.config.AgentPolicyParameters;
import com.k2cybersecurity.intcodeagent.utils.CommonUtils;
import com.squareup.okhttp.Response;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.*;

public class GlobalPolicyParameterPullST {

    private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

    final private static Object lock = new Object();
    public static final String VERSION = "version";
    public static final String CANCEL_CURRENT_TASK_OF_GLOBAL_POLICY_PULL = "Cancel current task of global policy pull.";

    private ScheduledExecutorService executorService;

    private Map<String, String> queryParam = new HashMap<>();

    public static GlobalPolicyParameterPullST instance;

    private ScheduledFuture future;

    public static GlobalPolicyParameterPullST getInstance() {
        if (instance == null) {
            synchronized (lock) {
                if (instance == null) {
                    instance = new GlobalPolicyParameterPullST();
                }
            }
        }
        return instance;
    }

    private GlobalPolicyParameterPullST() {
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
        future = executorService.schedule(runnable, 5, TimeUnit.MINUTES);
        logger.log(LogLevel.INFO, "policy fetch schedule thread started successfully!!!", PolicyPullST.class.getName());
    }

    Runnable runnable = new Runnable() {
        @Override
        public void run() {
            try {
                boolean pullRequired = isGlobalPolicyPullRequired(AgentUtils.getInstance().getAgentPolicyParameters().getVersion());
                if (!pullRequired) {
                    return;
                }
                AgentPolicyParameters parameters = getPolicyParamters();
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

    private AgentPolicyParameters getPolicyParamters() {
        try {
            Response response = HttpClient.getInstance().doGet(IRestClientConstants.POLICY_PARAMETER, null, queryParam, null, false);
            if (response.isSuccessful()) {
                logger.log(LogLevel.INFO, String.format(IAgentConstants.POLICY_VERSION_CHANGED_POLICY_PARAMETER_PULL_REQUIRED_RESPONSE_BODY, response.code(), response.body().string()), GlobalPolicyParameterPullST.class.getName());
                return HttpClient.getInstance().readResponse(response.body().byteStream(), AgentPolicyParameters.class);
            } else {
                logger.log(LogLevel.ERROR, String.format(IAgentConstants.POLICY_NO_CHANGE_IN_GLOBAL_POLICY_PARAMETERS_RESPONSE_BODY, response.code(), response.body().string()), GlobalPolicyParameterPullST.class.getName());
            }
        } catch (Exception e) {
            logger.log(LogLevel.ERROR, String.format(IAgentConstants.POLICY_PARAMETER_VERSION_CHECK_FAILED_MESSAGE_CAUSE, e.getMessage(), e.getCause()), GlobalPolicyParameterPullST.class.getName());
        }
        return new AgentPolicyParameters();
    }

    private boolean isGlobalPolicyPullRequired(String version) {
        try {
            queryParam.put(VERSION, version);
            Response response = HttpClient.getInstance().doGet(IRestClientConstants.POLICY_PARAMETER, null, queryParam, null, false);
            if (response.isSuccessful()) {
                logger.log(LogLevel.INFO, String.format(IAgentConstants.POLICY_VERSION_CHANGED_POLICY_PARAMETER_PULL_REQUIRED_RESPONSE_BODY, response.code(), response.body().string()), GlobalPolicyParameterPullST.class.getName());
                return true;
            } else {
                logger.log(LogLevel.ERROR, String.format(IAgentConstants.POLICY_NO_CHANGE_IN_GLOBAL_POLICY_PARAMETERS_RESPONSE_BODY, response.code(), response.body().string()), GlobalPolicyParameterPullST.class.getName());
            }
        } catch (Exception e) {
            logger.log(LogLevel.ERROR, String.format(IAgentConstants.POLICY_PARAMETER_VERSION_CHECK_FAILED_MESSAGE_CAUSE, e.getMessage(), e.getCause()), GlobalPolicyParameterPullST.class.getName());
        }
        return false;
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
