package com.newrelic.agent.security.instrumentator.utils;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import com.newrelic.agent.security.AgentInfo;
import com.newrelic.agent.security.intcodeagent.filelogging.FileLoggerThreadPool;
import com.newrelic.agent.security.intcodeagent.filelogging.LogLevel;
import com.newrelic.agent.security.intcodeagent.models.collectorconfig.CollectorConfig;
import com.newrelic.agent.security.intcodeagent.models.collectorconfig.CustomerInfo;
import com.newrelic.agent.security.intcodeagent.models.collectorconfig.K2ServiceInfo;
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
    public static final String VALIDATOR_URL = "validator-url";
    private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

    private static CollectorConfigurationUtils instance;

    private static final Object lock = new Object();

    private ObjectMapper yamlMapper = new ObjectMapper(new YAMLFactory());

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
    public static CollectorConfig populateCollectorConfig() {
        CollectorConfig collectorConfig = new CollectorConfig();
        String validatorServiceEndpointUrl = null;
        String apiAccessor = null;
        String hostName = null;

        // Loading validatorServiceEndpointUrl value
        if(System.getenv().containsKey("K2_VALIDATOR_SERVICE_URL")){
            validatorServiceEndpointUrl = System.getenv().get("K2_VALIDATOR_SERVICE_URL");
        } else if(NewRelic.getAgent().getConfig().getValue("security.validator_service_endpoint_url") != null) {
            validatorServiceEndpointUrl = NewRelic.getAgent().getConfig().getValue("security.validator_service_endpoint_url");
        } else {
            logger.log(LogLevel.ERROR, "Unable to find Validator service endpoint url. Please specify either env K2_VALIDATOR_SERVICE_URL or NR config key 'security.validator_service_endpoint_url'", CollectorConfigurationUtils.class.getName());
            //TODO raise exception
        }

        // Loading apiAccessor value
        if(System.getenv().containsKey("K2_API_ACCESSOR_TOKEN")){
            apiAccessor = System.getenv().get("K2_API_ACCESSOR_TOKEN");
        } else if(NewRelic.getAgent().getConfig().getValue("license_key") != null) {
            apiAccessor = NewRelic.getAgent().getConfig().getValue("license_key");
        } else {
            logger.log(LogLevel.ERROR, "Unable to find api accessor key. Please specify either env K2_API_ACCESSOR_TOKEN or NR config key 'license_key'", CollectorConfigurationUtils.class.getName());
            //TODO raise exception
        }

        // Loading resourceServiceEndpointUrl value
        if (System.getenv().containsKey("K2_NODE_NAME")) {
            hostName = System.getenv().get("K2_NODE_NAME");
        } else {
            hostName = AgentInfo.getInstance().getLinkingMetadata().getOrDefault(INRSettingsKey.HOSTNAME, StringUtils.EMPTY);
        }

        collectorConfig.setNodeId(AgentInfo.getInstance().getLinkingMetadata().getOrDefault(INRSettingsKey.NR_ENTITY_GUID, StringUtils.EMPTY));
        collectorConfig.setNodeName(hostName);
        collectorConfig.setNodeGroupTags(Collections.emptySet());

        CustomerInfo customerInfo = new CustomerInfo();
        customerInfo.setApiAccessorToken(apiAccessor);
        collectorConfig.setCustomerInfo(customerInfo);

        String accountId = NewRelic.getAgent().getConfig().getValue("account_id");
        if (StringUtils.isBlank(accountId)) {
            logger.log(LogLevel.ERROR, "Unable to find account id.", CollectorConfigurationUtils.class.getName());
            //TODO raise exception
        } else {
            collectorConfig.getCustomerInfo().setAccountId(accountId);
        }

        K2ServiceInfo serviceInfo = new K2ServiceInfo();
        serviceInfo.setValidatorServiceEndpointURL(validatorServiceEndpointUrl);
        collectorConfig.setK2ServiceInfo(serviceInfo);
        AgentUtils.getInstance().getStatusLogValues().put(VALIDATOR_URL, validatorServiceEndpointUrl);
        return collectorConfig;
    }

}
