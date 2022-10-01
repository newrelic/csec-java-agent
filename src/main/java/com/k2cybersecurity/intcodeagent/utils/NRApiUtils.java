package com.k2cybersecurity.intcodeagent.utils;

import com.k2cybersecurity.instrumentator.utils.AgentUtils;
import com.k2cybersecurity.instrumentator.utils.CollectorConfigurationUtils;
import com.newrelic.api.agent.NewRelic;
import org.apache.commons.lang3.StringUtils;

public class NRApiUtils {

    public static final String LOGS = "logs";

    public static String getLogPath() {
        if (AgentUtils.getInstance().isStandaloneMode()) {
            return LOGS;
        }
        return NewRelic.getAgent().getConfig().getValue("log_file_path", LOGS);
    }

    public static String getLicenseKey() {
        if (AgentUtils.getInstance().isStandaloneMode()) {
            return CollectorConfigurationUtils.getInstance().getCollectorConfig().getCustomerInfo().getApiAccessorToken();
        }
        return NewRelic.getAgent().getConfig().getValue("license_key", StringUtils.EMPTY);
    }
}
