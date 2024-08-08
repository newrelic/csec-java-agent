package com.newrelic.agent.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.introspect.JacksonAnnotationIntrospector;
import com.newrelic.agent.security.instrumentator.os.OSVariables;
import com.newrelic.agent.security.instrumentator.os.OsVariablesInstance;
import com.newrelic.agent.security.instrumentator.utils.AgentUtils;
import com.newrelic.agent.security.intcodeagent.exceptions.RestrictionModeException;
import com.newrelic.agent.security.intcodeagent.filelogging.FileLoggerThreadPool;
import com.newrelic.agent.security.intcodeagent.models.collectorconfig.AgentMode;
import com.newrelic.agent.security.intcodeagent.utils.CronExpression;
import com.newrelic.api.agent.security.Agent;
import com.newrelic.api.agent.security.schema.policy.*;
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
import java.text.ParseException;
import java.time.Instant;
import java.util.*;
import java.util.logging.Level;

import static com.newrelic.agent.security.util.IUtilConstants.*;

public class AgentConfig {

    public static final String CLEANING_STATUS_SNAPSHOTS_FROM_LOG_DIRECTORY_MAX_S_FILE_COUNT_REACHED_REMOVED_S = "Cleaning status-snapshots from snapshots directory, max %s file count reached removed : %s";

    public static final String AGENT_JAR_LOCATION = "agent_jar_location";
    public static final String AGENT_HOME = "agent_home";
    public static final String INVALID_CRON_EXPRESSION_PROVIDED_FOR_IAST_RESTRICTED_MODE = "Invalid cron expression provided for IAST Restricted Mode";
    public static final String ACCOUNT_ID_IS_REQUIRED_FOR_IAST_RESTRICTED_MODE = "Account ID is required for IAST Restricted Mode";
    public static final String ACCOUNT_ID_LOCATION = "account_id_location";
    public static final String ACCOUNT_ID_KEY = "account_id_key";
    public static final String ROUTE = "route";
    private String NR_CSEC_HOME;

    private String logLevel;

    private String groupName;

    private AgentMode agentMode;

    private CollectorConfig config = new CollectorConfig();

    private boolean isNRSecurityEnabled;

    private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

    private OSVariables osVariables;

    private AgentConfig(){
    }

    public long instantiate(){
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
        Agent.getCustomNoticeErrorParameters().put(IUtilConstants.SECURITY_MODE, groupName);
        // Enable low severity hooks
        // Set required LogLevel
        logLevel = applyRequiredLogLevel();

        //Instantiation call please do not move or repeat this.
        osVariables = OsVariablesInstance.instantiate().getOsVariables();

        instantiateAgentMode(groupName);

        return trigerIAST();
    }

    public long trigerIAST() {
        try {
            if(agentMode.getIastScan().getEnabled() && agentMode.getIastScan().getRestricted()){
                long date = agentMode.getIastScan().getRestrictionCriteria().getScanTime().getNextScanTime().getTime();
                long currentTime = Instant.now().toEpochMilli();
                return date-currentTime;
            }
        } catch (Exception e){
            //TODO send notice error
            System.err.println("[NR-CSEC-JA] Error while calculating next scan time for IAST Restricted Mode. IAST Restricted Mode will be disabled.");
            NewRelic.getAgent().getLogger().log(Level.WARNING, "[NR-CSEC-JA] Error while calculating next scan time for IAST Restricted Mode. IAST Restricted Mode will be disabled.");
            return Long.MAX_VALUE;
        }
        return 0;
    }

    private void instantiateAgentMode(String groupName) {
        this.agentMode = new AgentMode(groupName);
        switch (groupName){
            case IAST:
                readIastConfig();
                break;
            case RASP:
                readRaspConfig();
                break;
            case IAST_RESTRICTED:
                try {
                    readIastRestrictedConfig();
                } catch (RestrictionModeException e) {
                    System.err.println("[NR-CSEC-JA] Error while reading IAST Restricted Mode Configuration. IAST Restricted Mode will be disabled.");
                    NewRelic.getAgent().getLogger().log(Level.WARNING, "[NR-CSEC-JA] Error while reading IAST Restricted Mode Configuration. IAST Restricted Mode will be disabled.");
                    NewRelic.noticeError(e, Agent.getCustomNoticeErrorParameters(), true);
                    this.agentMode.getIastScan().setEnabled(false);
                }
                break;
            default:
                //this is default case which requires no changes
                break;
        }

    }

    private void readIastConfig() {
        this.agentMode.getIastScan().setEnabled(true);
        this.agentMode.getRaspScan().setEnabled(false);
    }

    private void readIastRestrictedConfig() throws RestrictionModeException {
        this.agentMode.getIastScan().setRestricted(true);
        Agent.getCustomNoticeErrorParameters().put(IAST_RESTRICTED, String.valueOf(true));
        RestrictionCriteria restrictionCriteria = this.agentMode.getIastScan().getRestrictionCriteria();
        restrictionCriteria.setAccountInfo(new AccountInfo(NewRelic.getAgent().getConfig().getValue(RESTRICTION_CRITERIA_ACCOUNT_INFO_ACCOUNT_ID)));
        if(restrictionCriteria.getAccountInfo().isEmpty()) {
            throw new RestrictionModeException(ACCOUNT_ID_IS_REQUIRED_FOR_IAST_RESTRICTED_MODE);
        }

        restrictionCriteria.getScanTime().setDuration(NewRelic.getAgent().getConfig().getValue(RESTRICTION_CRITERIA_SCAN_TIME_DURATION, 5));
        restrictionCriteria.getScanTime().setSchedule(NewRelic.getAgent().getConfig().getValue(RESTRICTION_CRITERIA_SCAN_TIME_SCHEDULE, "0 0 0 * * ?"));
        if(CronExpression.isValidExpression(restrictionCriteria.getScanTime().getSchedule())){
            try {
                restrictionCriteria.getScanTime().setNextScanTime(new CronExpression(restrictionCriteria.getScanTime().getSchedule()).getTimeAfter(new Date()));
            } catch (ParseException e) {
                throw new RestrictionModeException(INVALID_CRON_EXPRESSION_PROVIDED_FOR_IAST_RESTRICTED_MODE, e);
            }
        } else {
            throw new RestrictionModeException(INVALID_CRON_EXPRESSION_PROVIDED_FOR_IAST_RESTRICTED_MODE);
        }

        //Mapping parameters
        List<Map<String, String>> mappingParameters = NewRelic.getAgent().getConfig().getValue(RESTRICTION_CRITERIA_MAPPING_PARAMETERS, Collections.emptyList());
        for (Map<String, String> mappingParameter : mappingParameters) {
            MappingParameters matchingCriteria = new MappingParameters(HttpParameterLocation.valueOf(mappingParameter.get(ACCOUNT_ID_LOCATION)), mappingParameter.get(ACCOUNT_ID_KEY));
//            MappingParameters matchingCriteria = mapper.convertValue(mappingParameter, MappingParameters.class);
            restrictionCriteria.getMappingParameters().add(matchingCriteria);
        }
        //Skip Scan Parameters
        restrictionCriteria.getSkipScanParameters().setBody(NewRelic.getAgent().getConfig().getValue(RESTRICTION_CRITERIA_SKIP_SCAN_PARAMETERS_BODY, Collections.emptyList()));
        restrictionCriteria.getSkipScanParameters().setHeader(NewRelic.getAgent().getConfig().getValue(RESTRICTION_CRITERIA_SKIP_SCAN_PARAMETERS_HEADER, Collections.emptyList()));
        restrictionCriteria.getSkipScanParameters().setQuery(NewRelic.getAgent().getConfig().getValue(RESTRICTION_CRITERIA_SKIP_SCAN_PARAMETERS_QUERY, Collections.emptyList()));

        //Strict Criteria
        List<Map<String, String>> strictCriteria = NewRelic.getAgent().getConfig().getValue(RESTRICTION_CRITERIA_STRICT, Collections.emptyList());
        for (Map<String, String> strictCriterion : strictCriteria) {
            StrictMappings matchingCriteria = new StrictMappings(strictCriterion.get(ROUTE), HttpParameterLocation.valueOf(strictCriterion.get(ACCOUNT_ID_LOCATION)), strictCriterion.get(ACCOUNT_ID_KEY));
            restrictionCriteria.getStrictMappings().add(matchingCriteria);
        }

    }

    private void readRaspConfig() {
        this.agentMode.getIastScan().setEnabled(false);
        this.agentMode.getRaspScan().setEnabled(true);
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
        Agent.getCustomNoticeErrorParameters().put(IUtilConstants.NR_SECURITY_HOME, NR_CSEC_HOME);
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

    public String getLogLevel() {
        return logLevel;
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

    public AgentMode getAgentMode() {
        return agentMode;
    }
}
