package com.k2cybersecurity.instrumentator.utils;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import com.k2cybersecurity.instrumentator.K2Instrumentator;
import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import com.k2cybersecurity.intcodeagent.filelogging.LogLevel;
import com.k2cybersecurity.intcodeagent.models.collectorconfig.CollectorConfig;
import com.k2cybersecurity.intcodeagent.models.collectorconfig.CustomerInfo;
import com.k2cybersecurity.intcodeagent.models.collectorconfig.K2ServiceInfo;
import com.k2cybersecurity.intcodeagent.models.javaagent.IdentifierEnvs;
import com.newrelic.api.agent.NewRelic;
import org.apache.commons.lang3.StringUtils;

import java.util.Collections;

/**
 * Utility class for K2 policy and configuration handling
 */
public class CollectorConfigurationUtils {
    public static final String ERROR_WHILE_READING_NLC_COLLECTOR_CONFIG_S_S = "Error while reading NLC Collector config: %s : %s";
    public static final String ERROR_WHILE_READING_NLC_COLLECTOR_CONFIG = "Error while reading NLC Collector config:";
    public static final String ERROR_WHILE_READING_ALC_COLLECTOR_CONFIG_S_S = "Error while reading ALC Collector config: %s : %s";
    public static final String ERROR_WHILE_READING_ALC_COLLECTOR_CONFIG = "Error while reading ALC Collector config:";
    public static final String NODE_LEVEL_CONFIGURATION_LOADED = "Node Level Configuration loaded ";
    public static final String NODE_LEVEL_CONFIGURATION_WAS_NOT_PROVIDED = "Node Level Configuration was not provided.";
    public static final String APPLICATION_LEVEL_CONFIGURATION_LOADED = "Application Level Configuration loaded ";
    public static final String APPLICATION_LEVEL_CONFIGURATION_WAS_NOT_PROVIDED = "Application Level Configuration was not provided.";
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

    /*
        Create required collector config from NR config and env vars.
     */
    public boolean populateCollectorConfig() {
        String validatorServiceEndpointUrl = null;
        String resourceServiceEndpointUrl = null;
        String apiAccessor = null;
        String hostName = null;

        // Loading validatorServiceEndpointUrl value
        if(System.getenv().containsKey("K2_VALIDATOR_SERVICE_URL")){
            validatorServiceEndpointUrl = System.getenv().get("K2_VALIDATOR_SERVICE_URL");
        } else if(NewRelic.getAgent().getConfig().getValue("security.validator_service_endpoint_url") != null) {
            validatorServiceEndpointUrl = NewRelic.getAgent().getConfig().getValue("security.validator_service_endpoint_url");
        } else {
            logger.log(LogLevel.ERROR, "Unable to find Validator service endpoint url. Please specify either env K2_VALIDATOR_SERVICE_URL or NR config key 'security.validator_service_endpoint_url'", K2Instrumentator.class.getName());
            return false;
        }

        // Loading resourceServiceEndpointUrl value
        if(System.getenv().containsKey("K2_RESOURCE_SERVICE_URL")){
            resourceServiceEndpointUrl = System.getenv().get("K2_RESOURCE_SERVICE_URL");
        } else if(NewRelic.getAgent().getConfig().getValue("security.resource_service_endpoint_url") != null) {
            resourceServiceEndpointUrl = NewRelic.getAgent().getConfig().getValue("security.resource_service_endpoint_url");
        } else {
            logger.log(LogLevel.ERROR, "Unable to find Resource service endpoint url. Please specify either env K2_RESOURCE_SERVICE_URL or NR config key 'security.resource_service_endpoint_url'", K2Instrumentator.class.getName());
            return false;
        }

        // Loading apiAccessor value
        if(System.getenv().containsKey("K2_API_ACCESSOR_TOKEN")){
            apiAccessor = System.getenv().get("K2_API_ACCESSOR_TOKEN");
        } else if(NewRelic.getAgent().getConfig().getValue("license_key") != null) {
            apiAccessor = NewRelic.getAgent().getConfig().getValue("license_key");
        } else {
            logger.log(LogLevel.ERROR, "Unable to find api accessor key. Please specify either env K2_API_ACCESSOR_TOKEN or NR config key 'license_key'", K2Instrumentator.class.getName());
            return false;
        }

        // Loading resourceServiceEndpointUrl value
        if (System.getenv().containsKey("K2_NODE_NAME")) {
            hostName = System.getenv().get("K2_NODE_NAME");
        } else {
            hostName = AgentUtils.getInstance().getLinkingMetadata().getOrDefault(INRSettingsKey.HOSTNAME, StringUtils.EMPTY);
        }
//        else {
//            logger.log(LogLevel.ERROR, "Unable to find api accessor key. Please specify either env K2_API_ACCESSOR_TOKEN or NR config key 'license_key'", K2Instrumentator.class.getName());
//            return false;
//        }

        this.collectorConfig.setNodeId(AgentUtils.getInstance().getLinkingMetadata().getOrDefault(INRSettingsKey.NR_ENTITY_GUID, StringUtils.EMPTY));
        this.collectorConfig.setNodeName(hostName);
        this.collectorConfig.setNodeGroupTags(Collections.emptySet());

        CustomerInfo customerInfo = new CustomerInfo();
        customerInfo.setApiAccessorToken(apiAccessor);
        this.collectorConfig.setCustomerInfo(customerInfo);

        K2ServiceInfo serviceInfo = new K2ServiceInfo();
        serviceInfo.setResourceServiceEndpointURL(resourceServiceEndpointUrl);
        serviceInfo.setValidatorServiceEndpointURL(validatorServiceEndpointUrl);
        this.collectorConfig.setK2ServiceInfo(serviceInfo);
        return true;
    }

    private boolean validateCollectorConfig(IdentifierEnvs kind, String nodeLevelConfigurationPath) {
//        if (collectorConfig.getCustomerInfo() == null || collectorConfig.getCustomerInfo().isEmpty()) {
//            logger.log(LogLevel.ERROR, String.format("Improper CustomerInfo provided in collector configuration. Exiting : %s", collectorConfig.getCustomerInfo()), CollectorConfigurationUtils.class.getName());
//            return false;
//        }
        if (collectorConfig.getK2ServiceInfo() == null || collectorConfig.getK2ServiceInfo().isEmpty()) {
            logger.log(LogLevel.ERROR, String.format("[STEP-1][ENV] Improper K2ServiceInfo provided in collector configuration. Exiting : %s", collectorConfig), CollectorConfigurationUtils.class.getName());
            return false;
        }

        switch (kind) {
            // NLC required
            case HOST:
            case CONTAINER:
            case POD:
                // TODO : Alternative of nodeID needed here
//                if (StringUtils.isAnyBlank(collectorConfig.getNodeIp(), collectorConfig.getNodeId())) {
//                    logger.log(LogLevel.ERROR, String.format("Improper node details provided in collector configuration. Exiting : %s", collectorConfig), CollectorConfigurationUtils.class.getName());
//                    logger.log(LogLevel.ERROR, String.format("[STEP-1][ENV] Node level configuration was not found or incorrect on path : %s", nodeLevelConfigurationPath), CollectorConfigurationUtils.class.getName());
//                    return false;
//                }
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
