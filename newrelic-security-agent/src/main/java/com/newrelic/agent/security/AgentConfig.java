package com.newrelic.agent.security;

import com.newrelic.agent.security.instrumentator.os.OSVariables;
import com.newrelic.agent.security.instrumentator.os.OsVariablesInstance;
import com.newrelic.agent.security.instrumentator.utils.AgentUtils;
import com.newrelic.agent.security.intcodeagent.filelogging.FileLoggerThreadPool;
import com.newrelic.agent.security.intcodeagent.filelogging.LogLevel;
import com.newrelic.agent.security.intcodeagent.filelogging.LogWriter;
import com.newrelic.agent.security.intcodeagent.models.collectorconfig.CollectorConfig;
import com.newrelic.agent.security.intcodeagent.utils.CommonUtils;
import com.newrelic.agent.security.util.IUtilConstants;
import com.newrelic.api.agent.NewRelic;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.comparator.LastModifiedFileComparator;
import org.apache.commons.io.filefilter.FileFilterUtils;
import org.apache.commons.lang3.StringUtils;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Collection;

import static com.newrelic.agent.security.util.IUtilConstants.PERMISSIONS_ALL;

public class AgentConfig {

    public static final String CLEANING_STATUS_SNAPSHOTS_FROM_LOG_DIRECTORY_MAX_S_FILE_COUNT_REACHED_REMOVED_S = "Cleaning status-snapshots from snapshots directory, max %s file count reached removed : %s";

    private static AgentConfig instance;

    private static final Object lock = new Object();
    private String K2_HOME;

    private String logLevel;

    private String groupName;

    private CollectorConfig config = new CollectorConfig();

    private boolean isNRSecurityEnabled;

    private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

    private OSVariables osVariables;

    private AgentConfig(){
    }

    public void instantiate(){
        //Set k2 home path
        boolean validHomePath = setK2HomePath();
        isNRSecurityEnabled = NewRelic.getAgent().getConfig().getValue(IUtilConstants.NR_SECURITY_ENABLED, false);
        // Set required Group
        groupName = applyRequiredGroup();
        // Set required LogLevel
        logLevel = applyRequiredLogLevel();

        //Instantiation call please do not move or repeat this.
        osVariables = OsVariablesInstance.instantiate().getOsVariables();
    }

    public static AgentConfig getInstance(){
        if (instance == null) {
            synchronized (lock) {
                if (instance == null) {
                    instance = new AgentConfig();
                }
            }
        }
        return instance;
    }

    private String applyRequiredGroup() {
        String groupName = NewRelic.getAgent().getConfig().getValue(IUtilConstants.SECURITY_MODE);
        if(StringUtils.isBlank(groupName)) {
            groupName = IUtilConstants.IAST;
        }
        AgentUtils.getInstance().getStatusLogValues().put(IUtilConstants.GROUP_NAME, groupName);
        return groupName;
    }

    private String applyRequiredLogLevel() {
        String logLevel = IUtilConstants.INFO;
        if (StringUtils.isNotBlank(NewRelic.getAgent().getConfig().getValue(IUtilConstants.NR_LOG_LEVEL))) {
            logLevel = NewRelic.getAgent().getConfig().getValue(IUtilConstants.NR_LOG_LEVEL);
        }

        try {
            LogWriter.setLogLevel(LogLevel.valueOf(StringUtils.upperCase(logLevel)));
        } catch (Exception e) {
            LogWriter.setLogLevel(LogLevel.INFO);
            logLevel = LogLevel.INFO.name();
        }
        AgentUtils.getInstance().getStatusLogValues().put(IUtilConstants.LOG_LEVEL, logLevel);
        return logLevel;
    }

    public boolean setK2HomePath() {
        if (NewRelic.getAgent().getConfig().getValue("agent_home") != null) {
            K2_HOME = NewRelic.getAgent().getConfig().getValue("agent_home");
        } else {
            K2_HOME = ".";
        }
        Path k2homePath = Paths.get(K2_HOME, IUtilConstants.NR_SECURITY_HOME);
        CommonUtils.forceMkdirs(k2homePath, "rwxrwxrwx");
        K2_HOME = k2homePath.toString();
        AgentUtils.getInstance().getStatusLogValues().put("k2-home", K2_HOME);
        AgentUtils.getInstance().getStatusLogValues().put("k2-home-permissions", String.valueOf(k2homePath.toFile().canWrite() && k2homePath.toFile().canRead()));
        AgentUtils.getInstance().getStatusLogValues().put("agent-location",
                NewRelic.getAgent().getConfig().getValue("agent_jar_location"));
        if (!isValidK2HomePath(K2_HOME)) {
            System.err.println("[K2-JA] Incomplete startup env parameters provided : Missing or Incorrect K2_HOME. Collector exiting.");
            return false;
        }
        return true;
    }

    private static boolean isValidK2HomePath(String k2Home) {
        if (StringUtils.isNotBlank(k2Home) && Paths.get(k2Home).toFile().isDirectory()) {
            long avail = 0;
            try {
                avail = Files.getFileStore(Paths.get(k2Home)).getUsableSpace();
            } catch (Exception e) {
                return true;
            }

            if (avail > FileUtils.ONE_GB) {
                return true;
            }
            System.err.println(String.format("[K2-JA] Insufficient disk space available to the location %s is : %s", k2Home, FileUtils.byteCountToDisplaySize(avail)));
            return false;
        }
        return false;
    }

    public void populateAgentPolicy(){
        AgentUtils.getInstance().instantiateDefaultPolicy();
    }

    public void populateAgentPolicyParameters(){
        //TODO instantiate policy parameters if required
    }

    public CollectorConfig getConfig() {
        return config;
    }

    public void setConfig(CollectorConfig config) {
        this.config = config;
    }

    public void createSnapshotDirectory() {
        Path snapshotDir = Paths.get(osVariables.getSnapshotDir());
        // Remove any file with this name from target.
        if (!snapshotDir.toFile().isDirectory()) {
            FileUtils.deleteQuietly(snapshotDir.toFile());
        }
        CommonUtils.forceMkdirs(snapshotDir, PERMISSIONS_ALL);
    }

    private void keepMaxStatusLogFiles(int max) {
        Collection<File> statusFiles = FileUtils.listFiles(new File(osVariables.getSnapshotDir()), FileFilterUtils.trueFileFilter(), null);
        if (statusFiles.size() >= max) {
            File[] sortedStatusFiles = statusFiles.toArray(new File[0]);
            Arrays.sort(sortedStatusFiles, LastModifiedFileComparator.LASTMODIFIED_COMPARATOR);
            FileUtils.deleteQuietly(sortedStatusFiles[0]);
            logger.log(LogLevel.INFO, String.format(CLEANING_STATUS_SNAPSHOTS_FROM_LOG_DIRECTORY_MAX_S_FILE_COUNT_REACHED_REMOVED_S, max, sortedStatusFiles[0].getAbsolutePath()), FileLoggerThreadPool.class.getName());
        }
    }

    public void setupSnapshotDir() {
        createSnapshotDirectory();
        keepMaxStatusLogFiles(100);
    }

    public String getGroupName() {
        return groupName;
    }

    public boolean isNRSecurityEnabled() {
        return isNRSecurityEnabled;
    }

    public void setNRSecurityEnabled(boolean NRSecurityEnabled) {
        isNRSecurityEnabled = NRSecurityEnabled;
    }

    public String getK2Home() {
        return K2_HOME;
    }
}
