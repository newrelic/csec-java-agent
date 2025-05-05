package com.newrelic.api.agent.security;

import com.newrelic.agent.security.AgentConfig;
import com.newrelic.agent.security.util.IUtilConstants;
import com.newrelic.api.agent.Config;
import com.newrelic.api.agent.NewRelic;
import com.newrelic.api.agent.Transaction;
import com.newrelic.api.agent.security.instrumentation.helpers.ThreadLocalLockHelper;
import com.newrelic.api.agent.security.schema.SecurityMetaData;
import org.junit.Assert;
import org.junit.Test;
import org.mockito.Answers;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;

public class NewRelicSecurityTest {

    @Test
    public void getAgentTest() {
        Assert.assertEquals(Agent.class, NewRelicSecurity.getAgent().getClass());
    }

    @Test
    public void isHookProcessingActiveTest() {
        MockedStatic<NewRelic> nrMock = Mockito.mockStatic(NewRelic.class, Answers.RETURNS_DEEP_STUBS);
        MockedStatic<AgentConfig> configMock = Mockito.mockStatic(AgentConfig.class, Answers.CALLS_REAL_METHODS);
        MockedStatic<Agent> csecAgentMock = Mockito.mockStatic(Agent.class, Answers.CALLS_REAL_METHODS);
        try {

            nrMock.when(AgentConfig::getInstance).thenReturn(Mockito.mock(AgentConfig.class));
            nrMock.when(AgentConfig.getInstance()::isNRSecurityEnabled).thenReturn(true);

            nrMock.when(Agent::getInstance).thenReturn(Mockito.mock(Agent.class));
            nrMock.when(Agent.getInstance()::isSecurityActive).thenReturn(true);


            nrMock.when(NewRelic::getAgent).thenReturn(Mockito.mock(com.newrelic.api.agent.Agent.class));
            nrMock.when(NewRelic.getAgent()::getTransaction).thenReturn(Mockito.mock(Transaction.class));
            nrMock.when(NewRelic.getAgent().getTransaction()::getSecurityMetaData).thenReturn(Mockito.mock(SecurityMetaData.class));
            NewRelicSecurity.markAgentAsInitialised();

            Thread.currentThread().setName("TEST-CSEC");
            System.out.println(NewRelicSecurity.isHookProcessingActive());
            Assert.assertTrue(NewRelicSecurity.isHookProcessingActive());

        } finally {
            clean(nrMock, configMock, csecAgentMock);
        }

    }

    @Test
    public void isInternalThreadTest() {
        Assert.assertFalse(NewRelicSecurity.isInternalThread());

        Thread.currentThread().setName("NR-CSEC");
        Assert.assertTrue(NewRelicSecurity.isInternalThread());
    }

    public static void clean(MockedStatic<?>... mockedStatic) {
        for (MockedStatic<?> aStatic : mockedStatic) {
            aStatic.reset();
            aStatic.clearInvocations();
            aStatic.close();
        }
    }
}
