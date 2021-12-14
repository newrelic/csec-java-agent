/**
 * DirectoryWatcher.java
 * <p>
 * Copyright (C) 2017 - k2 Cyber Security, Inc. All rights reserved.
 * <p>
 * This software is proprietary information of k2 Cyber Security, Inc and
 * constitutes valuable trade secrets of k2 Cyber Security, Inc. You shall
 * not disclose this information and shall use it only in accordance with the
 * terms of License.
 * <p>
 * K2 CYBER SECURITY, INC MAKES NO REPRESENTATIONS OR WARRANTIES ABOUT THE
 * SUITABILITY OF THE SOFTWARE, EITHER EXPRESS OR IMPLIED, INCLUDING BUT
 * NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE, OR NON-INFRINGEMENT. K2 CYBER SECURITY, INC SHALL
 * NOT BE LIABLE FOR ANY DAMAGES SUFFERED BY LICENSEE AS A RESULT OF USING,
 * MODIFYING OR DISTRIBUTING THIS SOFTWARE OR ITS DERIVATIVES.
 * <p>
 * "K2 Cyber Security, Inc"
 */
package com.k2cybersecurity.instrumentator.utils;

import com.k2cybersecurity.instrumentator.K2Instrumentator;
import com.k2cybersecurity.instrumentator.httpclient.HttpClient;
import com.k2cybersecurity.instrumentator.httpclient.IRestClientConstants;
import com.k2cybersecurity.instrumentator.os.OSVariables;
import com.k2cybersecurity.instrumentator.os.OsVariablesInstance;
import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import com.k2cybersecurity.intcodeagent.filelogging.LogLevel;
import com.k2cybersecurity.intcodeagent.logging.IAgentConstants;
import com.k2cybersecurity.intcodeagent.models.config.AgentPolicy;
import com.k2cybersecurity.intcodeagent.schedulers.PolicyPullST;
import com.k2cybersecurity.intcodeagent.utils.CommonUtils;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.filefilter.DirectoryFileFilter;
import org.apache.commons.io.filefilter.NotFileFilter;
import org.apache.commons.io.filefilter.TrueFileFilter;
import org.apache.commons.lang3.StringUtils;

import java.io.File;
import java.io.IOException;
import java.nio.file.*;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.TimeUnit;

/**
 * DirectoryWatcher is provides a watch service that watches for changes and
 * events in registered directories.
 *
 * @author Team AppPerfect
 * @version 1.0
 */
public class DirectoryWatcher {

    private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

    /**
     * Instance of {@link WatchService}
     */
    private static WatchService watchService;

    private static Set<String> directoriesBeingWatched;

    private static Thread directoryWatcherThread;

    private static OSVariables osVariables = OsVariablesInstance.getInstance().getOsVariables();

    private static Instant policyLastUpdated = Instant.now();

    static {
        try {
            watchService = FileSystems.getDefault().newWatchService();
            directoriesBeingWatched = new HashSet<>();
//			startMonitorDaemon();
        } catch (IOException e) {
            logger.log(LogLevel.ERROR, "Error occured ", e, DirectoryWatcher.class.getName());
        }
    }

    public static Set<String> getDirectoriesBeingWatched() {
        return directoriesBeingWatched;
    }

    public static boolean isWatcherThreadAlive() {
        if (directoryWatcherThread != null)
            return directoryWatcherThread.isAlive();
        return false;
    }

    /**
     * Watch directories to monitor a directory for changes so that it can perform
     * actions when files are updated or created or deleted.
     *
     * @param dirPath     the dir path to be registered for monitoring
     * @param isRecursive is recursive (to register inner directories as well)
     */
    public static void watchDirectories(List<String> dirPath, boolean isRecursive) {
        directoriesBeingWatched.addAll(dirPath);
        if (!isRecursive) {
            for (int i = 0; i < dirPath.size(); i++)
                try {
                    File watchDirPath = new File(dirPath.get(i));
                    if (!watchDirPath.exists()) {
                        return;
                    } else {
                        logger.log(LogLevel.INFO, "dirPaths in watcher: " + watchDirPath, DirectoryWatcher.class.getName());
                    }
                    directoriesBeingWatched.addAll(Arrays.asList(watchDirPath.list()));
                    Paths.get(dirPath.get(i)).register(watchService, StandardWatchEventKinds.ENTRY_CREATE,
                            StandardWatchEventKinds.ENTRY_MODIFY, StandardWatchEventKinds.ENTRY_DELETE);
                } catch (IOException e) {
                    logger.log(LogLevel.ERROR, "Error registering path to watcher: ", e, DirectoryWatcher.class.getName());
                }
            return;
        }
        Collection<File> allInnerDirectories = null;
        for (int i = 0; i < dirPath.size(); i++) {
            allInnerDirectories = FileUtils.listFilesAndDirs(new File(dirPath.get(i)), new NotFileFilter(TrueFileFilter.INSTANCE),
                    DirectoryFileFilter.DIRECTORY);
        }
        if (allInnerDirectories != null) {
            for (File allInnerDirectory : allInnerDirectories) {
                try {
                    directoriesBeingWatched.addAll(Arrays.asList(allInnerDirectory.list()));
                    Paths.get(allInnerDirectory.getAbsolutePath()).register(watchService,
                            StandardWatchEventKinds.ENTRY_MODIFY);
                } catch (IOException e) {
                    logger.log(LogLevel.ERROR, "Error registring path to watcher: ", e, DirectoryWatcher.class.getName());
                }
            }
        }
    }

    /**
     * Static method to start the monitoring daemon thread to watch registered
     * directories with the name "IntCode-watcher". The thread starts in static
     * bloack of same class, which makes the thread start on load time.
     */
    public static void startMonitorDaemon() {
        directoryWatcherThread = new Thread("K2-JC-watcher") {
            @Override
            public void run() {
                WatchKey key;
                try {
                    while ((key = watchService.take()) != null) {
                        Path watchDirs = (Path) key.watchable();
                        for (WatchEvent<?> event : key.pollEvents()) {
                            logger.log(LogLevel.DEBUG, String.format("Event kind: %s. File affected: %s", event.kind(), event.context()), DirectoryWatcher.class.getName());
                            if (event.context() != null) {
                                performAction(event, watchDirs);
                            } else
                                logger.log(LogLevel.ERROR, "Couldn't find the modified file name, event context found null: " +
                                        event, DirectoryWatcher.class.getName());
                        }
                        key.reset();
                    }
                } catch (InterruptedException e) {
                    logger.log(LogLevel.ERROR, "Error occurred : ", e, DirectoryWatcher.class.getName());
                }
            }
        };
        directoryWatcherThread.start();
    }

    private static void performAction(WatchEvent<?> event, Path watchDirs) {
        if (StringUtils.equals(event.context().toString(), AgentUtils.getInstance().getConfigLoadPath().getName())) {
            if (Instant.now().minusSeconds(5).isAfter(policyLastUpdated)) {
                updatedPolicy(event);
                policyLastUpdated = Instant.now();
                return;
            }
            logger.log(LogLevel.DEBUG, "Returning as policy was last updated in less than 60secs ", DirectoryWatcher.class.getName());
            return;
        }
    }

    private static void updatedPolicy(WatchEvent<?> event) {
            try {
                logger.log(LogLevel.INFO, "Config file updated locally!!!", DirectoryWatcher.class.getName());
                TimeUnit.SECONDS.sleep(1);
                AgentPolicy newPolicy = PolicyPullST.getInstance().populateConfig();
                if (newPolicy != null) {
                    if (StringUtils.equals(newPolicy.getVersion(), AgentUtils.getInstance().getAgentPolicy().getVersion())) {
                        return;
                    }
                    if (!CommonUtils.validateCollectorPolicySchema(newPolicy)) {
                        logger.log(LogLevel.WARN, String.format(IAgentConstants.UNABLE_TO_VALIDATE_AGENT_POLICY_DUE_TO_ERROR_FILE, AgentUtils.getInstance().getAgentPolicy()), PolicyPullST.class.getName());
                        CommonUtils.writePolicyToFile();
                        return;
                    }
                    if (PolicyPullST.getInstance().readAndApplyConfig(newPolicy)) {
                        try {
                            Map<String, String> queryParam = new HashMap<>();
                            queryParam.put("group", AgentUtils.getInstance().getGroupName());
                            queryParam.put("applicationUUID", K2Instrumentator.APPLICATION_UUID);

                            HttpClient.getInstance().doPost(IRestClientConstants.UPDATE_POLICY, null, queryParam, null, newPolicy, true);
                        } catch (Exception e) {
                            logger.log(LogLevel.WARN, String.format("Update policy to IC failed due to %s", e.getMessage()), DirectoryWatcher.class.getName());
                        }
                    }
                }
            } catch (Exception e) {
                logger.log(LogLevel.ERROR, "Config update was unsuccessful for configs at : " + AgentUtils.getInstance().getConfigLoadPath(), e, DirectoryWatcher.class.getName());
                CommonUtils.writePolicyToFile();
            }
    }
}
