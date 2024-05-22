package com.newrelic.agent.security;

import com.newrelic.agent.security.instrumentator.os.OSVariables;
import com.newrelic.agent.security.instrumentator.os.OsVariablesInstance;
import com.newrelic.agent.security.instrumentator.utils.AgentUtils;
import com.newrelic.agent.security.intcodeagent.filelogging.FileLoggerThreadPool;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import com.newrelic.agent.security.intcodeagent.filelogging.LogWriter;
import com.newrelic.agent.security.intcodeagent.models.collectorconfig.CollectorConfig;
import com.newrelic.agent.security.intcodeagent.utils.CommonUtils;
import com.newrelic.agent.security.util.IUtilConstants;
import com.newrelic.api.agent.NewRelic;
import com.newrelic.api.agent.security.instrumentation.helpers.LowSeverityHelper;
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

    private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

    private OSVariables osVariables;

    private AgentConfig(){
    }

    public void instantiate(){
        //Set k2 home path
        try {
            boolean validHomePath = setK2HomePath();
            System.out.println("New Relic Security Agent: Setting csec home path to directory:"+NR_CSEC_HOME);
        } catch (IOException e) {
            String tmpDir = System.getProperty("java.io.tmpdir");
            System.err.println("[NR-CSEC-JA] "+e.getMessage()+" Please find the error in  " + tmpDir + File.separator + "NR-CSEC-Logger.err");
            throw new RuntimeException("CSEC Agent Exiting!!! Unable to create csec home directory", e);
        }
        isNRSecurityEnabled = NewRelic.getAgent().getConfig().getValue(IUtilConstants.NR_SECURITY_ENABLED, false);
        // Set required Group
        groupName = applyRequiredGroup();
        // Enable low severity hooks
        // Set required LogLevel
        logLevel = applyRequiredLogLevel();

        //Instantiation call please do not move or repeat this.
        osVariables = OsVariablesInstance.instantiate().getOsVariables();
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

    public boolean setK2HomePath() throws IOException {
        String agentJarLocation = NewRelic.getAgent().getConfig().getValue(AGENT_JAR_LOCATION);
        if (NewRelic.getAgent().getConfig().getValue(AGENT_HOME) != null) {
            NR_CSEC_HOME = NewRelic.getAgent().getConfig().getValue(AGENT_HOME);
        } else if (StringUtils.isNotBlank(agentJarLocation)){
            //fallback to agent_jar_location as home
            NR_CSEC_HOME = agentJarLocation;
        } else {
            System.err.println("[NR-CSEC-JA] Missing or Incorrect system property `newrelic.home` or environment variable `NEWRELIC_HOME`. Collector exiting.");
            return false;
        }
        Path k2homePath = Paths.get(NR_CSEC_HOME, IUtilConstants.NR_SECURITY_HOME);
        if(!CommonUtils.forceMkdirs(k2homePath, DIRECTORY_PERMISSION)){
            System.err.println(String.format("[NR-CSEC-JA] CSEC home directory creation failed at %s", NR_CSEC_HOME));
            return false;
        }
        NR_CSEC_HOME = k2homePath.toString();
        AgentUtils.getInstance().getStatusLogValues().put("csec-home", NR_CSEC_HOME);
        AgentUtils.getInstance().getStatusLogValues().put("csec-home-permissions", String.valueOf(k2homePath.toFile().canWrite() && k2homePath.toFile().canRead()));
        AgentUtils.getInstance().getStatusLogValues().put("agent-location", agentJarLocation);
        if (!isValidK2HomePath(NR_CSEC_HOME)) {
            System.err.println("[NR-CSEC-JA] Incomplete startup env parameters provided : Missing or Incorrect 'newrelic.home'. Collector exiting.");
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
            System.err.println(String.format("[NR-CSEC-JA] Insufficient disk space available to the location %s is : %s", k2Home, FileUtils.byteCountToDisplaySize(avail)));
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

    public void createSnapshotDirectory() throws IOException {
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

    public String getK2Home() {
        return NR_CSEC_HOME;
    }
}
