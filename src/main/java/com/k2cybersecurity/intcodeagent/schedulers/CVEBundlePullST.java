package com.k2cybersecurity.intcodeagent.schedulers;

import com.k2cybersecurity.instrumentator.K2Instrumentator;
import com.k2cybersecurity.instrumentator.cve.scanner.CVEComponentsService;
import com.k2cybersecurity.instrumentator.cve.scanner.CVEScannerPool;
import com.k2cybersecurity.instrumentator.utils.AgentUtils;
import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import com.k2cybersecurity.intcodeagent.filelogging.LogLevel;
import com.k2cybersecurity.intcodeagent.models.javaagent.PolicyFetch;
import com.k2cybersecurity.intcodeagent.websocket.EventSendPool;
import com.k2cybersecurity.intcodeagent.websocket.FtpClient;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.net.ftp.FTPClient;

import java.util.List;
import java.util.concurrent.*;

public class CVEBundlePullST {

    private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

    final private static Object lock = new Object();

    private ScheduledExecutorService executorService;

    private Future future;

    private static CVEBundlePullST instance;

    private String platform;

    private String lastKnownCVEBundle;

    private CVEBundlePullST(String platform) {
        this.platform = platform;
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
        FTPClient ftpClient = FtpClient.getClient();
        try {
            List<String> availablePackages = FtpClient.listAllFiles(ftpClient, CVEComponentsService.getPackageRegex(platform));
            if (availablePackages.isEmpty()) {
                return;
            }

            String latestPackage = availablePackages.get(0);

            if (!StringUtils.equals(latestPackage, lastKnownCVEBundle)) {
                if (AgentUtils.getInstance().getAgentPolicy().getVulnerabilityScan().getCveScan().getEnableEnvScan()) {
                    //Run CVE scan on ENV
                    CVEScannerPool.getInstance().dispatchScanner(AgentUtils.getInstance().getInitMsg().getAgentInfo().getNodeId(), K2Instrumentator.APPLICATION_INFO_BEAN.getIdentifier().getKind().name(), K2Instrumentator.APPLICATION_INFO_BEAN.getIdentifier().getId(), false, true);
                    AgentUtils.getInstance().setCveEnvScanCompleted(true);
                }
                CVEScannerPool.getInstance().dispatchScanner(AgentUtils.getInstance().getInitMsg().getAgentInfo().getNodeId(), K2Instrumentator.APPLICATION_INFO_BEAN.getIdentifier().getKind().name(), K2Instrumentator.APPLICATION_INFO_BEAN.getIdentifier().getId(), false, false);
            }
        } finally {
            if (ftpClient != null) {
                try {
                    ftpClient.disconnect();
                } catch (Exception e) {
                }
            }
        }
    }

    public static CVEBundlePullST getInstance() {
        if (instance == null) {
            synchronized (lock) {
                if (instance == null) {
                    instance = new CVEBundlePullST(AgentUtils.getInstance().getPlatform());
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
