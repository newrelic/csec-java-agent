package com.newrelic.agent.security;

import com.newrelic.agent.security.util.IUtilConstants;
import com.newrelic.api.agent.NewRelic;
import org.apache.commons.io.FileUtils;
import org.junit.Assert;
import org.junit.Test;
import org.mockito.Answers;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import java.io.File;
import java.io.IOException;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;

public class AgentConfigTest {

    @Test
    public void applyRequiredGroup() {
        AgentConfig.getInstance().instantiate();
        Assert.assertEquals("IAST", AgentConfig.getInstance().getGroupName());
    }
    @Test
    public void applyRequiredGroup1() {
        try (MockedStatic<NewRelic> nrMock = Mockito.mockStatic(NewRelic.class, Answers.RETURNS_DEEP_STUBS)){
            nrMock.when(NewRelic.getAgent().getConfig().getValue(IUtilConstants.SECURITY_MODE)).thenReturn("RASP");
            nrMock.when(NewRelic.getAgent().getConfig().getValue(eq(IUtilConstants.NR_SECURITY_ENABLED), any())).thenReturn(false);
            AgentConfig.getInstance().instantiate();
            Assert.assertEquals("RASP", AgentConfig.getInstance().getGroupName());
            nrMock.reset();
            nrMock.clearInvocations();
        }
    }
    @Test
    public void isNRSecurityEnabled() {
        AgentConfig.getInstance().instantiate();
        Assert.assertFalse(AgentConfig.getInstance().isNRSecurityEnabled());
    }
    @Test
    public void setK2HomePath() {
        Assert.assertTrue(AgentConfig.getInstance().setK2HomePath());
    }
    @Test
    public void setK2HomePath1() throws IOException {
        String AGENT_HOME = "/tmp/file_"+ UUID.randomUUID();
        try (MockedStatic<NewRelic> nrMock = Mockito.mockStatic(NewRelic.class, Answers.RETURNS_DEEP_STUBS)){
            nrMock.when(NewRelic.getAgent().getConfig().getValue("agent_home")).thenReturn(AGENT_HOME);

            Assert.assertTrue(AgentConfig.getInstance().setK2HomePath());
            Assert.assertEquals(AGENT_HOME+"/nr-security-home", AgentConfig.getInstance().getK2Home());
            nrMock.reset();
            nrMock.clearInvocations();
        } finally {
            FileUtils.forceDeleteOnExit(new File(AGENT_HOME));
        }
    }
}
