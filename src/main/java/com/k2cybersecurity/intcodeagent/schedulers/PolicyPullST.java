package com.k2cybersecurity.intcodeagent.schedulers;

import com.k2cybersecurity.instrumentator.K2Instrumentator;
import com.k2cybersecurity.instrumentator.utils.AgentUtils;
import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import com.k2cybersecurity.intcodeagent.filelogging.LogLevel;
import com.k2cybersecurity.intcodeagent.models.javaagent.PolicyFetch;
import com.k2cybersecurity.intcodeagent.websocket.EventSendPool;
import com.k2cybersecurity.intcodeagent.websocket.WSClient;

import java.util.concurrent.*;

public class PolicyPullST {

    private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

    final private static Object lock = new Object();

    private ScheduledExecutorService executorService;

    private Future future;

    private static PolicyPullST instance;

    private PolicyPullST() {
        executorService = Executors.newSingleThreadScheduledExecutor(new ThreadFactory() {
            @Override
            public Thread newThread(Runnable r) {
                return new Thread(Thread.currentThread().getThreadGroup(), r,
                        "K2-pull-policy-st");
            }
        });
        executorService.schedule(runnable, 1, TimeUnit.MINUTES);
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
        PolicyFetch policyFetch = new PolicyFetch(K2Instrumentator.AGENT_GROUP, K2Instrumentator.APPLICATION_UUID);
        EventSendPool.getInstance().sendEvent(policyFetch.toString());
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
