package com.k2cybersecurity.instrumentator.utils;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import com.k2cybersecurity.intcodeagent.filelogging.LogLevel;
import com.k2cybersecurity.intcodeagent.models.collectorconfig.ApplicationLevelConfig;
import com.k2cybersecurity.intcodeagent.models.collectorconfig.CollectorConfig;
import com.k2cybersecurity.intcodeagent.models.collectorconfig.NodeLevelConfig;
import com.k2cybersecurity.intcodeagent.models.javaagent.AgentBasicInfo;
import com.k2cybersecurity.intcodeagent.models.javaagent.IdentifierEnvs;
import org.apache.commons.lang3.StringUtils;

import java.io.File;

public class CollectorConfigurationUtils {
    public static final String ERROR_WHILE_READING_NLC_COLLECTOR_CONFIG_S_S = "Error while reading NLC Collector config: %s : %s";
    public static final String ERROR_WHILE_READING_NLC_COLLECTOR_CONFIG = "Error while reading NLC Collector config:";
    public static final String ERROR_WHILE_READING_ALC_COLLECTOR_CONFIG_S_S = "Error while reading ALC Collector config: %s : %s";
    public static final String ERROR_WHILE_READING_ALC_COLLECTOR_CONFIG = "Error while reading ALC Collector config:";
    private final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

    private static CollectorConfigurationUtils instance;

    private static final Object lock = new Object();

    private ObjectMapper yamlMapper = new ObjectMapper(new YAMLFactory());

    private CollectorConfig collectorConfig = new CollectorConfig();

    private CollectorConfigurationUtils() {
    }

    public static CollectorConfigurationUtils getInstance() {
        if (instance == null) {
            synchronized (lock) {
                if (instance == null) {
                    instance = new CollectorConfigurationUtils();
                }
            }
        }
        return instance;
    }

    public boolean readCollectorConfig(IdentifierEnvs kind, String nodeLevelConfigurationPath, String applicationLevelConfigurationPath) {
        NodeLevelConfig nodeLevelConfig = new NodeLevelConfig();
        ApplicationLevelConfig applicationLevelConfig = new ApplicationLevelConfig();
        try {
            File nlcFile = new File(nodeLevelConfigurationPath);
            if (nlcFile.exists()) {
                nodeLevelConfig = yamlMapper.readValue(nlcFile, NodeLevelConfig.class);
                logger.log(LogLevel.INFO, "Node Level Configuration loaded " + nodeLevelConfig, CollectorConfigurationUtils.class.getName());
            } else {
                logger.log(LogLevel.WARNING, "Node Level Configuration was not provided.", CollectorConfigurationUtils.class.getName());
            }
        } catch (Throwable e) {
            logger.log(LogLevel.ERROR, String.format(ERROR_WHILE_READING_NLC_COLLECTOR_CONFIG_S_S, e.getMessage(), e.getCause()), CollectorConfigurationUtils.class.getName());
            logger.log(LogLevel.ERROR, ERROR_WHILE_READING_NLC_COLLECTOR_CONFIG, e, CollectorConfigurationUtils.class.getName());
        }
        try {
            File alcFile = new File(applicationLevelConfigurationPath);
            if (alcFile.exists()) {
                applicationLevelConfig = yamlMapper.readValue(alcFile, ApplicationLevelConfig.class);
                logger.log(LogLevel.INFO, "Application Level Configuration loaded " + applicationLevelConfig, CollectorConfigurationUtils.class.getName());
            } else {
                logger.log(LogLevel.WARNING, "Application Level Configuration was not provided.", CollectorConfigurationUtils.class.getName());
            }
        } catch (Throwable e) {
            logger.log(LogLevel.ERROR, String.format(ERROR_WHILE_READING_ALC_COLLECTOR_CONFIG_S_S, e.getMessage(), e.getCause()), CollectorConfigurationUtils.class.getName());
            logger.log(LogLevel.ERROR, ERROR_WHILE_READING_ALC_COLLECTOR_CONFIG, e, CollectorConfigurationUtils.class.getName());
        }

        setCollectorConfig(nodeLevelConfig, applicationLevelConfig);
        if (validateCollectorConfig(kind)) {
            AgentBasicInfo.setNodeId(CollectorConfigurationUtils.getInstance().getCollectorConfig().getNodeId());
            AgentBasicInfo.setCustomerId(CollectorConfigurationUtils.getInstance().getCollectorConfig().getCustomerInfo().getCustomerId());
            return true;
        }
        return false;
    }

    private void setCollectorConfig(NodeLevelConfig nodeLevelConfig, ApplicationLevelConfig applicationLevelConfig) {
        this.collectorConfig.setNodeId(nodeLevelConfig.getNodeId());
        this.collectorConfig.setNodeIp(nodeLevelConfig.getNodeIp());
        this.collectorConfig.setNodeName(nodeLevelConfig.getNodeName());
        this.collectorConfig.setNodeGroupTags(nodeLevelConfig.getNodeGroupTags());
        this.collectorConfig.setCustomerInfo(nodeLevelConfig.getCustomerInfo());
        this.collectorConfig.setK2ServiceInfo(nodeLevelConfig.getK2ServiceInfo());

        // Values available in ApplicationLevelConfig will override NodeLevelConfig (if applicable)
        if (applicationLevelConfig.getCustomerInfo() != null && !applicationLevelConfig.getCustomerInfo().isEmpty()) {
            this.collectorConfig.setCustomerInfo(applicationLevelConfig.getCustomerInfo());
        }
        if (applicationLevelConfig.getK2ServiceInfo() != null && !applicationLevelConfig.getK2ServiceInfo().isEmpty()) {
            this.collectorConfig.setK2ServiceInfo(applicationLevelConfig.getK2ServiceInfo());
        }
        this.collectorConfig.setAppInfo(applicationLevelConfig.getAppInfo());
    }

    private boolean validateCollectorConfig(IdentifierEnvs kind) {
//        if (collectorConfig.getCustomerInfo() == null || collectorConfig.getCustomerInfo().isEmpty()) {
//            logger.log(LogLevel.ERROR, String.format("Improper CustomerInfo provided in collector configuration. Exiting : %s", collectorConfig.getCustomerInfo()), CollectorConfigurationUtils.class.getName());
//            return false;
//        }
        if (collectorConfig.getK2ServiceInfo() == null || collectorConfig.getK2ServiceInfo().isEmpty()) {
            logger.log(LogLevel.ERROR, String.format("Improper K2ServiceInfo provided in collector configuration. Exiting : %s", collectorConfig), CollectorConfigurationUtils.class.getName());
            return false;
        }

        switch (kind) {
            // NLC required
            case HOST:
            case CONTAINER:
            case POD:
                if (StringUtils.isAnyBlank(collectorConfig.getNodeIp(), collectorConfig.getNodeId())) {
                    logger.log(LogLevel.ERROR, String.format("Improper node details provided in collector configuration. Exiting : %s", collectorConfig), CollectorConfigurationUtils.class.getName());
                    return false;
                }
                break;

            // NLC not required
            case ECS:
            case FARGATE:
            case LAMBDA:
                break;
        }
        return true;
    }

    public CollectorConfig getCollectorConfig() {
        return collectorConfig;
    }
}
