package com.newrelic.agent.security;

import com.newrelic.agent.security.instrumentator.os.OSVariables;
import com.newrelic.agent.security.instrumentator.os.OsVariablesInstance;
import com.newrelic.agent.security.instrumentator.utils.AgentUtils;
import com.newrelic.agent.security.intcodeagent.exceptions.SecurityNoticeError;
import com.newrelic.agent.security.intcodeagent.filelogging.FileLoggerThreadPool;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
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
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import static com.newrelic.agent.security.util.IUtilConstants.DIRECTORY_PERMISSION;

public class AgentConfig {

    public static final String CLEANING_STATUS_SNAPSHOTS_FROM_LOG_DIRECTORY_MAX_S_FILE_COUNT_REACHED_REMOVED_S = "Cleaning status-snapshots from snapshots directory, max %s file count reached removed : %s";

    public static final String AGENT_JAR_LOCATION = "agent_jar_location";
    public static final String AGENT_HOME = "agent_home";
    private String NR_CSEC_HOME;

    private String logLevel;

    private String groupName;

    private CollectorConfig config = new CollectorConfig();

    private boolean isNRSecurityEnabled;

    private static FileLoggerThreadPool logger;

    private OSVariables osVariables;

    private Map<String, String> noticeErrorCustomParams = new HashMap<>();

    private AgentConfig(){
    }

    public void instantiate(){
        //Set k2 home path
        boolean validHomePath = setSecurityHomePath();
        if(validHomePath) {
            System.out.println("New Relic Security Agent: Setting csec home path to directory: " + NR_CSEC_HOME);
        }
        isNRSecurityEnabled = NewRelic.getAgent().getConfig().getValue(IUtilConstants.NR_SECURITY_ENABLED, false);
        // Set required Group
        groupName = applyRequiredGroup();
        //Instantiation call please do not move or repeat this.
        osVariables = OsVariablesInstance.instantiate().getOsVariables();

        logger = FileLoggerThreadPool.getInstance();
        // Set required LogLevel
        logLevel = applyRequiredLogLevel();
    }

    private static final class InstanceHolder {
        static final AgentConfig instance = new AgentConfig();
    }

    public static AgentConfig getInstance(){
        return InstanceHolder.instance;
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
        String logLevel;
        Object value = NewRelic.getAgent().getConfig().getValue(IUtilConstants.NR_LOG_LEVEL);
        if(value instanceof Boolean) {
            logLevel = IUtilConstants.OFF;
        } else {
            logLevel = NewRelic.getAgent().getConfig().getValue(IUtilConstants.NR_LOG_LEVEL, IUtilConstants.INFO);
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

    public boolean setSecurityHomePath(){
        noticeErrorCustomParams.put(IUtilConstants.LOG_FILE_PATH, NewRelic.getAgent().getConfig().getValue(IUtilConstants.LOG_FILE_PATH));
        noticeErrorCustomParams.put(AGENT_JAR_LOCATION, NewRelic.getAgent().getConfig().getValue(AGENT_JAR_LOCATION));
        noticeErrorCustomParams.put(AGENT_HOME, NewRelic.getAgent().getConfig().getValue(AGENT_HOME));
        if(NewRelic.getAgent().getConfig().getValue(IUtilConstants.LOG_FILE_PATH) != null) {
            NR_CSEC_HOME = NewRelic.getAgent().getConfig().getValue(IUtilConstants.LOG_FILE_PATH);
        } else if (NewRelic.getAgent().getConfig().getValue(AGENT_JAR_LOCATION) != null) {
            NR_CSEC_HOME = NewRelic.getAgent().getConfig().getValue(AGENT_JAR_LOCATION);
        } else if (NewRelic.getAgent().getConfig().getValue(AGENT_HOME) != null) {
            //system property `newrelic.home` or environment variable `NEWRELIC_HOME`
            NR_CSEC_HOME = NewRelic.getAgent().getConfig().getValue(AGENT_HOME);
        } else {
            NewRelic.noticeError(new SecurityNoticeError("CSEC home directory creation failed, reason directory not found. Please check the agent configs"), noticeErrorCustomParams, true);
            System.err.println("[NR-CSEC-JA] CSEC home directory not found. Please check the agent configs or system property `newrelic.home` or environment variable `NEWRELIC_HOME`.");
            return false;
        }
        Path SecurityhomePath = Paths.get(NR_CSEC_HOME, IUtilConstants.NR_SECURITY_HOME);
        NR_CSEC_HOME = SecurityhomePath.toString();
        try {
            noticeErrorCustomParams.put("CSEC_HOME", SecurityhomePath.toString());
            if(!CommonUtils.forceMkdirs(SecurityhomePath, DIRECTORY_PERMISSION)){
                NewRelic.noticeError(String.format("CSEC home directory creation failed, reason : %s", NR_CSEC_HOME), noticeErrorCustomParams, true);
                System.err.printf("[NR-CSEC-JA] CSEC home directory creation failed at %s%n", NR_CSEC_HOME);
                return false;
            }
        } catch (IOException e) {
            NewRelic.noticeError(new SecurityNoticeError(String.format("CSEC home directory creation failed, reason %s. Please check the agent configs", e.getMessage()), e), noticeErrorCustomParams, true);
            return false;
        }
        AgentUtils.getInstance().getStatusLogValues().put("csec-home", NR_CSEC_HOME);
        AgentUtils.getInstance().getStatusLogValues().put("csec-home-permissions", String.valueOf(SecurityhomePath.toFile().canWrite() && SecurityhomePath.toFile().canRead()));
        AgentUtils.getInstance().getStatusLogValues().put("agent-location", NewRelic.getAgent().getConfig().getValue(AGENT_JAR_LOCATION));
        return isValidSecurityHomePath(NR_CSEC_HOME);
    }

    private boolean isValidSecurityHomePath(String securityHome) {
        if (StringUtils.isNotBlank(securityHome) && Paths.get(securityHome).toFile().isDirectory()) {
            long avail = 0;
            try {
                avail = Files.getFileStore(Paths.get(securityHome)).getUsableSpace();
            } catch (Exception e) {
                return true;
            }

            if (avail > FileUtils.ONE_GB) {
                return true;
            }
            noticeErrorCustomParams.put("CSEC_HOME_DISK_AVL_BYTES", String.valueOf(avail));
            NewRelic.noticeError("CSEC home directory creation failed, reason : Insufficient disk space available to the location " + securityHome + " is : " + FileUtils.byteCountToDisplaySize(avail), noticeErrorCustomParams, true);
            System.err.println(String.format("[NR-CSEC-JA] Insufficient disk space available to the location %s is : %s", securityHome, FileUtils.byteCountToDisplaySize(avail)));
            return false;
        }
        NewRelic.noticeError("CSEC home directory creation failed, reason : CSEC home directory not found :"+securityHome, noticeErrorCustomParams, true);
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

    public void createSnapshotDirectory() throws IOException {
        if (osVariables.getSnapshotDir() == null){
            return;
        }
        Path snapshotDir = Paths.get(osVariables.getSnapshotDir());
        // Remove any file with this name from target.
        if (!snapshotDir.toFile().isDirectory()) {
            FileUtils.deleteQuietly(snapshotDir.toFile());
        }
        CommonUtils.forceMkdirs(snapshotDir, DIRECTORY_PERMISSION);
    }

    private void keepMaxStatusLogFiles(int max) {
        Collection<File> statusFiles = FileUtils.listFiles(new File(osVariables.getSnapshotDir()), FileFilterUtils.trueFileFilter(), null);
        if (statusFiles.size() >= max) {
            File[] sortedStatusFiles = statusFiles.toArray(new File[0]);
            Arrays.sort(sortedStatusFiles, LastModifiedFileComparator.LASTMODIFIED_COMPARATOR);
            FileUtils.deleteQuietly(sortedStatusFiles[0]);
            logger.log(LogLevel.INFO, String.format(CLEANING_STATUS_SNAPSHOTS_FROM_LOG_DIRECTORY_MAX_S_FILE_COUNT_REACHED_REMOVED_S, max, sortedStatusFiles[0].getAbsolutePath()), AgentConfig.class.getName());
        }
    }

    public void setupSnapshotDir() {
        try {
            createSnapshotDirectory();
            keepMaxStatusLogFiles(100);
        } catch (Exception e) {
            logger.log(LogLevel.WARNING, String.format("Snapshot directory creation failed !!! Please check file permissions. error:%s ", e.getMessage()), e, AgentConfig.class.getName());
        }
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

    public String getSecurityHome() {
        return NR_CSEC_HOME;
    }
}
