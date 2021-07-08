package com.k2cybersecurity.intcodeagent.schedulers;

import com.k2cybersecurity.instrumentator.K2Instrumentator;
import com.k2cybersecurity.instrumentator.cve.scanner.CVEComponentsService;
import com.k2cybersecurity.instrumentator.cve.scanner.CVEScannerPool;
import com.k2cybersecurity.instrumentator.cve.scanner.ICVEConstants;
import com.k2cybersecurity.instrumentator.os.OsVariablesInstance;
import com.k2cybersecurity.instrumentator.utils.AgentUtils;
import com.k2cybersecurity.instrumentator.utils.NameFileFilter;
import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import com.k2cybersecurity.intcodeagent.filelogging.LogLevel;
import com.k2cybersecurity.intcodeagent.models.javaagent.CVEPackageInfo;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;

import java.io.File;
import java.util.Collection;
import java.util.concurrent.*;

public class CVEBundlePullST {

    private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

    final private static Object lock = new Object();

    private ScheduledExecutorService executorService;

    private Future future;

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

    private void task() {
        CVEPackageInfo packageInfo = CVEComponentsService.getCVEPackageInfo();
        logger.log(LogLevel.DEBUG, packageInfo.toString() + " :: " + CVEScannerPool.getInstance().getPackageInfo(), CVEBundlePullST.class.getName());
        if (CVEScannerPool.getInstance().getPackageInfo() == null || !StringUtils.equals(packageInfo.getLatestServiceVersion(), CVEScannerPool.getInstance().getPackageInfo().getLatestServiceVersion())) {
            Collection<File> cvePackages = FileUtils.listFiles(new File(OsVariablesInstance.getInstance().getOsVariables().getCvePackageBaseDir()), new NameFileFilter(ICVEConstants.LOCALCVESERVICE), null);
            logger.log(LogLevel.DEBUG, ICVEConstants.FILES_TO_DELETE + cvePackages, CVEBundlePullST.class.getName());
            cvePackages.forEach(FileUtils::deleteQuietly);
            if (AgentUtils.getInstance().getAgentPolicy().getVulnerabilityScan().getCveScan().getEnableEnvScan()) {
                //Run CVE scan on ENV
                CVEScannerPool.getInstance().dispatchScanner(AgentUtils.getInstance().getInitMsg().getAgentInfo().getNodeId(), K2Instrumentator.APPLICATION_INFO_BEAN.getIdentifier().getKind().name(), K2Instrumentator.APPLICATION_INFO_BEAN.getIdentifier().getId(), false, true);
                AgentUtils.getInstance().setCveEnvScanCompleted(true);
            }
            CVEScannerPool.getInstance().dispatchScanner(AgentUtils.getInstance().getInitMsg().getAgentInfo().getNodeId(), K2Instrumentator.APPLICATION_INFO_BEAN.getIdentifier().getKind().name(), K2Instrumentator.APPLICATION_INFO_BEAN.getIdentifier().getId(), false, false);
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
