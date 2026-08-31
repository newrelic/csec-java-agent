package com.newrelic.agent.security.intcodeagent.utils;

import com.newrelic.agent.security.AgentConfig;
import com.newrelic.agent.security.intcodeagent.models.collectorconfig.CollectorConfig;
import com.newrelic.agent.security.intcodeagent.models.collectorconfig.CustomerInfo;
import com.newrelic.agent.security.intcodeagent.models.javaagent.ApplicationRuntimeError;
import com.newrelic.agent.security.intcodeagent.models.javaagent.LogMessageException;
import com.newrelic.api.agent.security.NewRelicSecurityTest;
import com.newrelic.api.agent.security.schema.HttpRequest;
import org.junit.Assert;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

@FixMethodOrder(value = MethodSorters.NAME_ASCENDING)
public class RuntimeErrorReporterTest {
    @Test
    public void addApplicationRuntimeError1Test() {
        AgentConfig.getInstance().setConfig(new CollectorConfig());
        AgentConfig.getInstance().getConfig().setCustomerInfo(new CustomerInfo());
        AgentConfig.getInstance().getConfig().getCustomerInfo().setAccountId("1");

        ApplicationRuntimeError error = new ApplicationRuntimeError(Mockito.mock(HttpRequest.class), new LogMessageException(new Exception(), 1, 1), "", "", "1");


        RuntimeErrorReporter.getInstance().addApplicationRuntimeError(error);
        Assert.assertFalse(RuntimeErrorReporter.getInstance().errors.isEmpty());
        Assert.assertEquals(1, RuntimeErrorReporter.getInstance().errors.size());
        Assert.assertEquals(1, error.getCounter().get());
    }

    @Test
    public void addApplicationRuntimeError2Test() {
        AgentConfig.getInstance().setConfig(new CollectorConfig());
        AgentConfig.getInstance().getConfig().setCustomerInfo(new CustomerInfo());
        AgentConfig.getInstance().getConfig().getCustomerInfo().setAccountId("1");

        ApplicationRuntimeError error = new ApplicationRuntimeError(Mockito.mock(HttpRequest.class), new LogMessageException(new Exception(), 1, 1), "server-error", "app-uuid", "2");
        RuntimeErrorReporter.getInstance().addApplicationRuntimeError(error);
        RuntimeErrorReporter.getInstance().addApplicationRuntimeError(error);
        Assert.assertFalse(RuntimeErrorReporter.getInstance().errors.isEmpty());
        Assert.assertEquals(2, RuntimeErrorReporter.getInstance().errors.size());
        Assert.assertEquals(2, error.getCounter().get());

    }

    @Test
    public void reportApplicationRuntimeErrorTest() {
        RuntimeErrorReporter.getInstance().reportApplicationRuntimeError();
        Assert.assertTrue(RuntimeErrorReporter.getInstance().errors.isEmpty());
    }
}
