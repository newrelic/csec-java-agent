package com.newrelic.agent.security.instrumentator.utils;

import com.newrelic.agent.security.AgentInfo;
import com.newrelic.agent.security.intcodeagent.filelogging.FileLoggerThreadPool;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
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
        String validatorServiceEndpointUrl = NewRelic.getAgent().getConfig()
                .getValue("security.validator_service_url", "wss://csec.nr-data.net");
        K2ServiceInfo serviceInfo = new K2ServiceInfo();

        serviceInfo.setValidatorServiceEndpointURL(validatorServiceEndpointUrl);
        AgentUtils.getInstance().getStatusLogValues().put(VALIDATOR_URL, validatorServiceEndpointUrl);

        collectorConfig.setNodeId(AgentInfo.getInstance().getLinkingMetadata().getOrDefault(INRSettingsKey.NR_ENTITY_GUID, StringUtils.EMPTY));
        collectorConfig.setNodeName(AgentInfo.getInstance().getLinkingMetadata().getOrDefault(INRSettingsKey.HOSTNAME, StringUtils.EMPTY));
        collectorConfig.setNodeGroupTags(Collections.emptySet());

        CustomerInfo customerInfo = new CustomerInfo();
        customerInfo.setApiAccessorToken(parseLicenseKey(NewRelic.getAgent().getConfig().getValue("license_key")));
        collectorConfig.setCustomerInfo(customerInfo);

        String accountId = NewRelic.getAgent().getConfig().getValue("account_id");
        if (StringUtils.isBlank(accountId)) {
            logger.log(LogLevel.SEVERE, "Unable to find account id.", CollectorConfigurationUtils.class.getName());
            //TODO raise exception
        } else {
            collectorConfig.getCustomerInfo().setAccountId(accountId);
        }

        collectorConfig.setK2ServiceInfo(serviceInfo);
        return collectorConfig;
    }

    private static String parseLicenseKey(Object license_key) {
        if(license_key instanceof String){
            return StringUtils.strip((String) license_key, "'\"");
        }
        return "unknown_license_key";
    }

}
