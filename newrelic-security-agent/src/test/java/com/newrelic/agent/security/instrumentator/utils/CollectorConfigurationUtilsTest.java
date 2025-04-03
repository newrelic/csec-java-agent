package com.newrelic.agent.security.instrumentator.utils;

import com.newrelic.agent.security.AgentInfo;
import com.newrelic.agent.security.intcodeagent.filelogging.FileLoggerThreadPool;
import com.newrelic.agent.security.intcodeagent.models.collectorconfig.CollectorConfig;
import com.newrelic.agent.security.intcodeagent.models.collectorconfig.CustomerInfo;
import com.newrelic.agent.security.intcodeagent.models.collectorconfig.K2ServiceInfo;
import com.newrelic.api.agent.NewRelic;
import org.junit.Assert;

import org.junit.BeforeClass;
import org.junit.Test;
import org.mockito.Answers;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import static com.newrelic.api.agent.security.schema.StringUtils.EMPTY;

public class CollectorConfigurationUtilsTest {
    private final CustomerInfo customerInfo = new CustomerInfo();
    private final K2ServiceInfo k2ServiceInfo = new K2ServiceInfo();

    @BeforeClass
    public static void beforeClass() throws Exception {
        FileLoggerThreadPool.getInstance().initialiseLogger();
    }

    @Test
    public void testConfig() {
        customerInfo.setApiAccessorToken("unknown_license_key");
        k2ServiceInfo.setValidatorServiceEndpointURL("wss://csec.nr-data.net");

        CollectorConfig collectorConfig = CollectorConfigurationUtils.populateCollectorConfig();
        assertCollectorConfig(EMPTY, EMPTY, k2ServiceInfo, customerInfo, collectorConfig);
    }

    @Test
    public void testConfig1() {
        String val_url = "wss://csec.nr-data.test";
        String licenseKey = "license_key", accountId = "account_id";
        String id = "id", hostname = "host";
        customerInfo.setApiAccessorToken(licenseKey);
        customerInfo.setAccountId(accountId);
        k2ServiceInfo.setValidatorServiceEndpointURL(val_url);

        try (MockedStatic<NewRelic> nrMock = Mockito.mockStatic(NewRelic.class, Answers.RETURNS_DEEP_STUBS);
             MockedStatic<AgentInfo> agentInfoMock = Mockito.mockStatic(AgentInfo.class, Answers.RETURNS_DEEP_STUBS)) {

            nrMock.when(() -> NewRelic.getAgent().getConfig().getValue("security.validator_service_url", "wss://csec.nr-data.net")).thenReturn(val_url);
            nrMock.when(() -> NewRelic.getAgent().getConfig().getValue(licenseKey)).thenReturn(licenseKey);
            nrMock.when(() -> NewRelic.getAgent().getConfig().getValue(accountId)).thenReturn(accountId);
            agentInfoMock.when(() -> AgentInfo.getInstance().getLinkingMetadata().getOrDefault(INRSettingsKey.NR_ENTITY_GUID, EMPTY)).thenReturn(id);
            agentInfoMock.when(() -> AgentInfo.getInstance().getLinkingMetadata().getOrDefault(INRSettingsKey.HOSTNAME, EMPTY)).thenReturn(hostname);

            CollectorConfig collectorConfig = CollectorConfigurationUtils.populateCollectorConfig();
            assertCollectorConfig(id, hostname, k2ServiceInfo, customerInfo, collectorConfig);
        }
    }

    private void assertCollectorConfig(String nodeId, String nodeName, K2ServiceInfo k2ServiceInfo, CustomerInfo customerInfo, CollectorConfig actualConfig) {
        Assert.assertEquals(nodeId, actualConfig.getNodeId());
        Assert.assertEquals(nodeName, actualConfig.getNodeName());

        Assert.assertEquals(k2ServiceInfo.getValidatorServiceEndpointURL(), actualConfig.getK2ServiceInfo().getValidatorServiceEndpointURL());
        Assert.assertEquals(customerInfo, actualConfig.getCustomerInfo());
        Assert.assertEquals(customerInfo.getApiAccessorToken(), actualConfig.getCustomerInfo().getApiAccessorToken());
        Assert.assertEquals(customerInfo.getAccountId(), actualConfig.getCustomerInfo().getAccountId());
    }
}
