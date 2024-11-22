package com.newrelic.agent.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.introspect.JacksonAnnotationIntrospector;
import com.newrelic.agent.security.instrumentator.os.OSVariables;
import com.newrelic.agent.security.instrumentator.os.OsVariablesInstance;
import com.newrelic.agent.security.instrumentator.utils.AgentUtils;
import com.newrelic.agent.security.intcodeagent.exceptions.RestrictionModeException;
import com.newrelic.agent.security.intcodeagent.exceptions.SecurityNoticeError;
import com.newrelic.agent.security.intcodeagent.exceptions.RestrictionModeException;
import com.newrelic.agent.security.intcodeagent.filelogging.FileLoggerThreadPool;
import com.newrelic.agent.security.intcodeagent.models.collectorconfig.AgentMode;
import com.newrelic.agent.security.intcodeagent.models.collectorconfig.ScanControllers;
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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.text.ParseException;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.stream.Collectors;

import static com.newrelic.agent.security.util.IUtilConstants.*;

public class AgentConfig {

    public static final String CLEANING_STATUS_SNAPSHOTS_FROM_LOG_DIRECTORY_MAX_S_FILE_COUNT_REACHED_REMOVED_S = "Cleaning status-snapshots from snapshots directory, max %s file count reached removed : %s";

    public static final String AGENT_JAR_LOCATION = "agent_jar_location";
    public static final String AGENT_HOME = "agent_home";
    public static final String INVALID_CRON_EXPRESSION_PROVIDED_FOR_IAST_RESTRICTED_MODE = "Invalid cron expression provided for IAST Mode";
    public static final String ACCOUNT_ID_IS_REQUIRED_FOR_IAST_RESTRICTED_MODE = "Account ID is required for IAST Restricted Mode";
    public static final String ACCOUNT_ID_LOCATION = "account_id_location";
    public static final String ACCOUNT_ID_KEY = "account_id_key";
    public static final String ROUTE = "route";
    public static final String MAPPING_PARAMETERS_ARE_REQUIRED_FOR_IAST_RESTRICTED_MODE = "Mapping Parameters are required for IAST Restricted Mode";
    public static final String DEFAULT_SCAN_SCHEDULE_EXPRESSION = "0 0 0 * * ?";
    public static final String INVALID_SECURITY_CONFIGURATION_FOR_MODE_IAST_RESTRICTED = "Invalid Security Configuration for mode IAST_RESTRICTED ";
    public static final String INVALID_SECURITY_CONFIGURATION = "Invalid Security Configuration ";
    private static final Logger log = LoggerFactory.getLogger(AgentConfig.class);
    private String NR_CSEC_HOME;

    private String logLevel;

    private String groupName;

    private AgentMode agentMode;

    private CollectorConfig config = new CollectorConfig();

    private boolean isNRSecurityEnabled;

    private static FileLoggerThreadPool logger;

    private OSVariables osVariables;

    private Map<String, String> noticeErrorCustomParams = new HashMap<>();

    private ScanControllers scanControllers = new ScanControllers();

    private AgentConfig(){
        this.agentMode = new AgentMode();
    }

    public long instantiate() throws RestrictionModeException {
        //Set k2 home path
        boolean validHomePath = setSecurityHomePath();
        if(validHomePath) {
            System.out.println("New Relic Security Agent: Setting Security home path to directory: " + NR_CSEC_HOME);
        }
        isNRSecurityEnabled = NewRelic.getAgent().getConfig().getValue(IUtilConstants.NR_SECURITY_ENABLED, false);
        // Set required Group
        groupName = applyRequiredGroup();
        Agent.getCustomNoticeErrorParameters().put(IUtilConstants.SECURITY_MODE, groupName);
        // Enable low severity hooks

        //Instantiation call please do not move or repeat this.
        osVariables = OsVariablesInstance.instantiate().getOsVariables();

        logger = FileLoggerThreadPool.getInstance();
        //Do not repeat this task
        logger.initialiseLogger();

        // Set required LogLevel
        logLevel = applyRequiredLogLevel();

        try {
            scanControllers.setScanInstanceCount(NewRelic.getAgent().getConfig().getValue(IUtilConstants.IAST_SCAN_INSTANCE_COUNT, 0));
        } catch (NumberFormatException | ClassCastException e){
            logger.log(LogLevel.FINEST, String.format("Error while reading IAST_SCAN_INSTANCE_COUNT %s , setting to default", NewRelic.getAgent().getConfig().getValue(IUtilConstants.IAST_SCAN_INSTANCE_COUNT)), AgentConfig.class.getName());
            scanControllers.setScanInstanceCount(0);
        }

        //Always set IAST Test Identifier after IAST_SCAN_INSTANCE_COUNT
        if(NewRelic.getAgent().getConfig().getValue(IUtilConstants.IAST_TEST_IDENTIFIER) instanceof String) {
            scanControllers.setIastTestIdentifier(NewRelic.getAgent().getConfig().getValue(IUtilConstants.IAST_TEST_IDENTIFIER));
            scanControllers.setScanInstanceCount(1);
        } else {
            scanControllers.setIastTestIdentifier(StringUtils.EMPTY);
        }


        instantiateAgentMode(groupName);

        return triggerIAST();
    }

    public long triggerIAST() throws RestrictionModeException {
        try {
            if(agentMode.getScanSchedule().getNextScanTime() != null) {
                logger.log(LogLevel.FINER, "Security Agent scan time is set to : " + agentMode.getScanSchedule().getNextScanTime(), AgentConfig.class.getName());
                long delay =  agentMode.getScanSchedule().getNextScanTime().getTime() - Instant.now().toEpochMilli();
                return (delay > 0)? delay : 0;
            }
        } catch (Exception e){
            RestrictionModeException restrictionModeException = new RestrictionModeException("Error while calculating next scan time for IAST Restricted Mode", e);
            NewRelic.noticeError(restrictionModeException, Agent.getCustomNoticeErrorParameters(), true);
            System.err.println("[NR-CSEC-JA] Error while calculating next scan time for IAST Restricted Mode. IAST Restricted Mode will be disabled.");
            NewRelic.getAgent().getLogger().log(Level.WARNING, "[NR-CSEC-JA] Error while calculating next scan time for IAST Restricted Mode. IAST Restricted Mode will be disabled.");
            throw restrictionModeException;
        }
        return 0;
    }

    private void instantiateAgentMode(String groupName) throws RestrictionModeException {
        try {
            readScanSchedule();
            readSkipScan();
        } catch (RestrictionModeException e){
            System.err.println("[NR-CSEC-JA] Error while reading IAST Scan Configuration. Security will be disabled.");
            NewRelic.getAgent().getLogger().log(Level.WARNING, "[NR-CSEC-JA] Error while reading IAST Scan Configuration. Security will be disabled. Message : {0}", e.getMessage());
            NewRelic.noticeError(e, Agent.getCustomNoticeErrorParameters(), true);
            AgentInfo.getInstance().agentStatTrigger(false);
            throw e;
        }
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
                    AgentInfo.getInstance().agentStatTrigger(false);
                    throw e;
                }
                break;
            case "IAST_MONITORING":
                readIastMonitoringConfig();
                break;
            default:
                //this is default case which requires no changes
                break;
        }

        updateSkipScanParameters();
        logger.log(LogLevel.INFO, String.format("Security Agent Modes and Config :  %s", agentMode), AgentConfig.class.getName());
    }

    private void readIastMonitoringConfig() {
        this.agentMode.getIastScan().setEnabled(false);
        this.agentMode.getRaspScan().setEnabled(false);
        this.agentMode.getIastScan().setRestricted(false);
        this.agentMode.getIastScan().setMonitoring(true);
        this.agentMode.getSkipScan().getIastDetectionCategory().setRxssEnabled(true);
    }

    private void readSkipScan() throws RestrictionModeException {
        try {
            agentMode.getSkipScan().setApis(NewRelic.getAgent().getConfig().getValue(SKIP_IAST_SCAN_API, Collections.emptyList()));
            agentMode.getSkipScan().getParameters().setQuery(NewRelic.getAgent().getConfig().getValue(SKIP_IAST_SCAN_PARAMETERS_QUERY, Collections.emptyList()).stream()
                    .map(Object::toString)
                    .collect(Collectors.toList()));
            agentMode.getSkipScan().getParameters().setHeader(NewRelic.getAgent().getConfig().getValue(SKIP_IAST_SCAN_PARAMETERS_HEADER, Collections.emptyList()).stream()
                    .map(Object::toString)
                    .collect(Collectors.toList()));
            agentMode.getSkipScan().getParameters().setBody(NewRelic.getAgent().getConfig().getValue(SKIP_IAST_SCAN_PARAMETERS_BODY, Collections.emptyList()).stream()
                    .map(Object::toString)
                    .collect(Collectors.toList()));
            agentMode.getSkipScan().getIastDetectionCategory().setInsecureSettingsEnabled(NewRelic.getAgent().getConfig().getValue(SKIP_INSECURE_SETTINGS, false));
            agentMode.getSkipScan().getIastDetectionCategory().setInvalidFileAccessEnabled(NewRelic.getAgent().getConfig().getValue(SKIP_INVALID_FILE_ACCESS, false));
            agentMode.getSkipScan().getIastDetectionCategory().setSqlInjectionEnabled(NewRelic.getAgent().getConfig().getValue(SKIP_SQL_INJECTION, false));
            agentMode.getSkipScan().getIastDetectionCategory().setNoSqlInjectionEnabled(NewRelic.getAgent().getConfig().getValue(SKIP_NOSQL_INJECTION, false));
            agentMode.getSkipScan().getIastDetectionCategory().setLdapInjectionEnabled(NewRelic.getAgent().getConfig().getValue(SKIP_LDAP_INJECTION, false));
            agentMode.getSkipScan().getIastDetectionCategory().setJavascriptInjectionEnabled(NewRelic.getAgent().getConfig().getValue(SKIP_JAVASCRIPT_INJECTION, false));
            agentMode.getSkipScan().getIastDetectionCategory().setCommandInjectionEnabled(NewRelic.getAgent().getConfig().getValue(SKIP_COMMAND_INJECTION, false));
            agentMode.getSkipScan().getIastDetectionCategory().setXpathInjectionEnabled(NewRelic.getAgent().getConfig().getValue(SKIP_XPATH_INJECTION, false));
            agentMode.getSkipScan().getIastDetectionCategory().setSsrfEnabled(NewRelic.getAgent().getConfig().getValue(SKIP_SSRF, false));
            agentMode.getSkipScan().getIastDetectionCategory().setRxssEnabled(NewRelic.getAgent().getConfig().getValue(SKIP_RXSS, false));
            agentMode.getSkipScan().getIastDetectionCategory().generateDisabledCategoriesCSV();
        } catch (ClassCastException | NumberFormatException e){
            throw new RestrictionModeException(INVALID_SECURITY_CONFIGURATION + e.getMessage(), e);
        }
    }

    private void readScanSchedule() throws RestrictionModeException {
        try {
            agentMode.getScanSchedule().setDelay(NewRelic.getAgent().getConfig().getValue(SCAN_TIME_DELAY, 0));
            agentMode.getScanSchedule().setDuration(NewRelic.getAgent().getConfig().getValue(SCAN_TIME_DURATION, 0));
            agentMode.getScanSchedule().setSchedule(NewRelic.getAgent().getConfig().getValue(SCAN_TIME_SCHEDULE, StringUtils.EMPTY));
            agentMode.getScanSchedule().setCollectSamples(NewRelic.getAgent().getConfig().getValue(SCAN_TIME_COLLECT_SAMPLES, false));
            if (agentMode.getScanSchedule().getDelay() > 0) {
                agentMode.getScanSchedule().setNextScanTime(new Date(Instant.now().toEpochMilli() + TimeUnit.MINUTES.toMillis(agentMode.getScanSchedule().getDelay())));
            } else if (StringUtils.isNotBlank(agentMode.getScanSchedule().getSchedule())) {
                agentMode.getScanSchedule().setScheduleOnce(false);
                if (CronExpression.isValidExpression(agentMode.getScanSchedule().getSchedule())) {
                    try {
                        agentMode.getScanSchedule().setNextScanTime(new CronExpression(agentMode.getScanSchedule().getSchedule()).getTimeAfter(new Date()));
                    } catch (ParseException e) {
                        throw new RestrictionModeException(INVALID_CRON_EXPRESSION_PROVIDED_FOR_IAST_RESTRICTED_MODE, e);
                    }
                } else {
                    throw new RestrictionModeException(INVALID_CRON_EXPRESSION_PROVIDED_FOR_IAST_RESTRICTED_MODE);
                }
            }
            agentMode.getScanSchedule().setDataCollectionTime(agentMode.getScanSchedule().getNextScanTime());
            if(agentMode.getScanSchedule().isCollectSamples()){
                agentMode.getScanSchedule().setNextScanTime(new Date(Instant.now().toEpochMilli()));
            }
        } catch (ClassCastException | NumberFormatException e){
            throw new RestrictionModeException(INVALID_SECURITY_CONFIGURATION + e.getMessage(), e);
        }
    }

    private void updateSkipScanParameters() {

        if(this.agentMode.getIastScan().getRestrictionCriteria().getMappingParameters().getBody().isEnabled()){
            this.agentMode.getSkipScan().getParameters().getBody().addAll(this.agentMode.getIastScan().getRestrictionCriteria().getMappingParameters().getBody().getLocations());
        }
        if(this.agentMode.getIastScan().getRestrictionCriteria().getMappingParameters().getQuery().isEnabled()){
            this.agentMode.getSkipScan().getParameters().getQuery().addAll(this.agentMode.getIastScan().getRestrictionCriteria().getMappingParameters().getQuery().getLocations());
        }
        if(this.agentMode.getIastScan().getRestrictionCriteria().getMappingParameters().getHeader().isEnabled()){
            this.agentMode.getSkipScan().getParameters().getHeader().addAll(this.agentMode.getIastScan().getRestrictionCriteria().getMappingParameters().getHeader().getLocations());
        }
    }

    private void readIastConfig() {
        this.agentMode.getIastScan().setEnabled(true);
        this.agentMode.getRaspScan().setEnabled(false);

    }

    private void readIastRestrictedConfig() throws RestrictionModeException {
        try {
            this.agentMode.getIastScan().setRestricted(true);
            Agent.getCustomNoticeErrorParameters().put(IAST_RESTRICTED, String.valueOf(true));
            RestrictionCriteria restrictionCriteria = this.agentMode.getIastScan().getRestrictionCriteria();
            restrictionCriteria.setAccountInfo(new AccountInfo(NewRelic.getAgent().getConfig().getValue(RESTRICTION_CRITERIA_ACCOUNT_INFO_ACCOUNT_ID)));
            if(restrictionCriteria.getAccountInfo().isEmpty()) {
                throw new RestrictionModeException(ACCOUNT_ID_IS_REQUIRED_FOR_IAST_RESTRICTED_MODE);
            }

            //Mapping parameters
            this.agentMode.getIastScan().getRestrictionCriteria().getMappingParameters().getBody().setEnabled(NewRelic.getAgent().getConfig().getValue(RESTRICTION_CRITERIA_MAPPING_PARAMETERS_BODY_ENABLED, false));
            this.agentMode.getIastScan().getRestrictionCriteria().getMappingParameters().getQuery().setEnabled(NewRelic.getAgent().getConfig().getValue(RESTRICTION_CRITERIA_MAPPING_PARAMETERS_QUERY_ENABLED, false));
            this.agentMode.getIastScan().getRestrictionCriteria().getMappingParameters().getHeader().setEnabled(NewRelic.getAgent().getConfig().getValue(RESTRICTION_CRITERIA_MAPPING_PARAMETERS_HEADER_ENABLED, false));
            this.agentMode.getIastScan().getRestrictionCriteria().getMappingParameters().getPath().setEnabled(NewRelic.getAgent().getConfig().getValue(RESTRICTION_CRITERIA_MAPPING_PARAMETERS_PATH_ENABLED, false));
            this.agentMode.getIastScan().getRestrictionCriteria().getMappingParameters().getBody().setLocations(NewRelic.getAgent().getConfig().getValue(RESTRICTION_CRITERIA_MAPPING_PARAMETERS_BODY_LOCATION, Collections.emptyList()).stream()
                    .map(Object::toString)
                    .collect(Collectors.toList()));
            this.agentMode.getIastScan().getRestrictionCriteria().getMappingParameters().getQuery().setLocations(NewRelic.getAgent().getConfig().getValue(RESTRICTION_CRITERIA_MAPPING_PARAMETERS_QUERY_LOCATION, Collections.emptyList()).stream()
                    .map(Object::toString)
                    .collect(Collectors.toList()));
            this.agentMode.getIastScan().getRestrictionCriteria().getMappingParameters().getHeader().setLocations(NewRelic.getAgent().getConfig().getValue(RESTRICTION_CRITERIA_MAPPING_PARAMETERS_HEADER_LOCATION, Collections.emptyList()).stream()
                    .map(Object::toString)
                    .collect(Collectors.toList()));

            //Strict Criteria
            List<Map<String, String>> strictCriteria = NewRelic.getAgent().getConfig().getValue(RESTRICTION_CRITERIA_STRICT, Collections.emptyList());
            for (Map<String, String> strictCriterion : strictCriteria) {
                StrictMappings matchingCriteria = new StrictMappings(strictCriterion.get(ROUTE), HttpParameterLocation.valueOf(strictCriterion.get(ACCOUNT_ID_LOCATION)), strictCriterion.get(ACCOUNT_ID_KEY));
                restrictionCriteria.getStrictMappings().add(matchingCriteria);
            }
        } catch (ClassCastException | NumberFormatException e){
            throw new RestrictionModeException(INVALID_SECURITY_CONFIGURATION_FOR_MODE_IAST_RESTRICTED + e.getMessage(), e);
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
        Agent.getCustomNoticeErrorParameters().put(IUtilConstants.NR_SECURITY_HOME, NR_CSEC_HOME);
        try {
            noticeErrorCustomParams.put("CSEC_HOME", SecurityhomePath.toString());
            Agent.getCustomNoticeErrorParameters().put(IUtilConstants.NR_SECURITY_HOME, NR_CSEC_HOME);
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

    public String getLogLevel() {
        return logLevel;
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

    public String getSecurityHome() {
        return NR_CSEC_HOME;
    }

    public AgentMode getAgentMode() {
        return agentMode;
    }

    public ScanControllers getScanControllers() {
        return scanControllers;
    }

    public void setScanControllers(ScanControllers scanControllers) {
        this.scanControllers = scanControllers;
    }
}
