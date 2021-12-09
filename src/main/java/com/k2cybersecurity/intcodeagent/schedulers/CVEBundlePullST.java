package com.k2cybersecurity.intcodeagent.schedulers;

import com.k2cybersecurity.instrumentator.K2Instrumentator;
import com.k2cybersecurity.instrumentator.cve.scanner.CVEComponentsService;
import com.k2cybersecurity.instrumentator.cve.scanner.CVEScannerPool;
import com.k2cybersecurity.instrumentator.utils.AgentUtils;
import com.k2cybersecurity.instrumentator.utils.CollectorConfigurationUtils;
import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import com.k2cybersecurity.intcodeagent.filelogging.LogLevel;
import com.k2cybersecurity.intcodeagent.models.javaagent.CVEPackageInfo;
import org.apache.commons.lang3.StringUtils;

import java.util.concurrent.*;

public class CVEBundlePullST {

    private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

    final private static Object lock = new Object();
    public static final String LOG_SEPARATOR = " :: ";

    private ScheduledExecutorService executorService;

    private ScheduledFuture future;

    private static CVEBundlePullST instance;

    private String lastKnownCVEBundle;

    private CVEBundlePullST() {
        executorService = Executors.newSingleThreadScheduledExecutor(new ThreadFactory() {
            @Override
            public Thread newThread(Runnable r) {
                return new Thread(Thread.currentThread().getThreadGroup(), r,
                        "K2-cve-bundle-st");
            }
        });
        executorService.schedule(runnable, 1, TimeUnit.MINUTES);
        logger.log(LogLevel.INFO, "CVE bundle fetch schedule thread started successfully!!!", CVEBundlePullST.class.getName());
    }

    private Runnable runnable = new Runnable() {
        @Override
        public void run() {
            try {
                task();
            } finally {
                if (AgentUtils.getInstance().getAgentPolicy().getVulnerabilityScan().getEnabled()
                        && AgentUtils.getInstance().getAgentPolicy().getVulnerabilityScan().getCveScan().getEnabled()
                        && AgentUtils.getInstance().getAgentPolicy().getVulnerabilityScan().getCveScan().getCveDefinitionUpdateInterval() > 0) {
                    future = executorService.schedule(runnable, AgentUtils.getInstance().getAgentPolicy().getVulnerabilityScan().getCveScan().getCveDefinitionUpdateInterval(), TimeUnit.MINUTES);
                }
            }
        }
    };

    public static void shutDown() {
        if (instance != null) {
            instance.cancelTask();
        }
    }

    private void task() {
        CVEPackageInfo packageInfo = CVEComponentsService.getCVEPackageInfo();
        logger.log(LogLevel.DEBUG, packageInfo.toString() + LOG_SEPARATOR + CVEScannerPool.getInstance().getPackageInfo(), CVEBundlePullST.class.getName());
        if (CVEScannerPool.getInstance().getPackageInfo() == null || !StringUtils.equals(packageInfo.getLatestServiceVersion(), CVEScannerPool.getInstance().getPackageInfo().getLatestServiceVersion())) {
            if (AgentUtils.getInstance().getAgentPolicy().getVulnerabilityScan().getCveScan().getEnableEnvScan()) {
                //Run CVE scan on ENV
                CVEScannerPool.getInstance().dispatchScanner(CollectorConfigurationUtils.getInstance().getCollectorConfig().getNodeId(), K2Instrumentator.APPLICATION_INFO_BEAN.getIdentifier().getKind().name(), K2Instrumentator.APPLICATION_INFO_BEAN.getIdentifier().getId(), false, true);
            }
            CVEScannerPool.getInstance().dispatchScanner(CollectorConfigurationUtils.getInstance().getCollectorConfig().getNodeId(), K2Instrumentator.APPLICATION_INFO_BEAN.getIdentifier().getKind().name(), K2Instrumentator.APPLICATION_INFO_BEAN.getIdentifier().getId(), false, false);
        }
    }

    public static CVEBundlePullST getInstance() {
        if (instance == null) {
            synchronized (lock) {
                if (instance == null) {
                    instance = new CVEBundlePullST();
                }
            }
        }
        return instance;
    }

    public String getLastKnownCVEBundle() {
        return lastKnownCVEBundle;
    }

    public void setLastKnownCVEBundle(String lastKnownCVEBundle) {
        this.lastKnownCVEBundle = lastKnownCVEBundle;
    }

    public void cancelTask() {
        if (future != null) {
            future.cancel(false);
        }
    }
}
