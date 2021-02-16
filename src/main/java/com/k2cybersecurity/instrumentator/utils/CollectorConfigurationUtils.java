package com.k2cybersecurity.instrumentator.utils;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import com.k2cybersecurity.intcodeagent.filelogging.LogLevel;
import com.k2cybersecurity.intcodeagent.models.collectorconfig.ApplicationLevelConfig;
import com.k2cybersecurity.intcodeagent.models.collectorconfig.CollectorConfig;
import com.k2cybersecurity.intcodeagent.models.collectorconfig.NodeLevelConfig;

import java.io.File;

public class CollectorConfigurationUtils {
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

    public boolean readCollectorConfig(String nodeLevelConfigurationPath, String applicationLevelConfigurationPath) {
        try {
            NodeLevelConfig nodeLevelConfig = yamlMapper.readValue(new File(nodeLevelConfigurationPath), NodeLevelConfig.class);
            logger.log(LogLevel.INFO, nodeLevelConfig.toString(), CollectorConfigurationUtils.class.getName());

            ApplicationLevelConfig applicationLevelConfig = yamlMapper.readValue(new File(applicationLevelConfigurationPath), ApplicationLevelConfig.class);
            logger.log(LogLevel.INFO, applicationLevelConfig.toString(), CollectorConfigurationUtils.class.getName());

            setCollectorConfig(nodeLevelConfig, applicationLevelConfig);
            return validateCollectorConfig();
        } catch (Throwable e) {
            logger.log(LogLevel.ERROR, String.format("Error while reading Collector config: %s : %s", e.getMessage(), e.getCause()), CollectorConfigurationUtils.class.getName());
            logger.log(LogLevel.ERROR, "Error while reading Collector config:", e, CollectorConfigurationUtils.class.getName());
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

    private boolean validateCollectorConfig() {
//        if (collectorConfig.getCustomerInfo() == null || collectorConfig.getCustomerInfo().isEmpty()) {
//            logger.log(LogLevel.ERROR, String.format("Improper CustomerInfo provided in collector configuration. Exiting : %s", collectorConfig.getCustomerInfo()), CollectorConfigurationUtils.class.getName());
//            return false;
//        }
        if (collectorConfig.getK2ServiceInfo() == null || collectorConfig.getK2ServiceInfo().isEmpty()) {
            logger.log(LogLevel.ERROR, String.format("Improper K2ServiceInfo provided in collector configuration. Exiting : %s", collectorConfig.getK2ServiceInfo()), CollectorConfigurationUtils.class.getName());
            return false;
        }

        // TODO : Place a ENV based check here if the NLC are applicable in the current env, then perform validation on nodeId & nodeIP.


        return true;
    }

    public CollectorConfig getCollectorConfig() {
        return collectorConfig;
    }
}
