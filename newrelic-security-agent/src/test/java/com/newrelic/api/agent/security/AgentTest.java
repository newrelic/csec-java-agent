package com.newrelic.api.agent.security;

import com.newrelic.agent.security.AgentInfo;
import com.newrelic.agent.security.instrumentator.utils.AgentUtils;
import com.newrelic.agent.security.intcodeagent.models.collectorconfig.CollectorConfig;
import com.newrelic.agent.security.intcodeagent.models.config.AgentPolicyParameters;
import com.newrelic.agent.security.intcodeagent.models.javaagent.Identifier;
import com.newrelic.agent.security.intcodeagent.models.javaagent.IdentifierEnvs;
import com.newrelic.api.agent.NewRelic;
import com.newrelic.api.agent.security.instrumentation.helpers.LowSeverityHelper;
import com.newrelic.api.agent.security.schema.AgentMetaData;
import com.newrelic.api.agent.security.schema.HttpRequest;
import com.newrelic.api.agent.security.schema.HttpResponse;
import com.newrelic.api.agent.security.schema.K2RequestIdentifier;
import com.newrelic.api.agent.security.schema.SecurityMetaData;
import com.newrelic.api.agent.security.schema.UserClassEntity;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.security.schema.operation.FileOperation;
import com.newrelic.api.agent.security.schema.policy.AgentPolicy;
import com.newrelic.api.agent.security.schema.policy.ApiBlocking;
import com.newrelic.api.agent.security.schema.policy.ProtectionMode;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.mockito.Answers;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import java.util.HashSet;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.doReturn;

public class AgentTest {
    private static final CollectorConfig collectorConfig = Mockito.mock(CollectorConfig.class);
    private static final AgentPolicy policy = Mockito.mock(AgentPolicy.class);
    private static final ProtectionMode mode = Mockito.mock(ProtectionMode.class);
    private static final ApiBlocking blocking = Mockito.mock(ApiBlocking.class);
    private static final AgentPolicyParameters parameters = Mockito.mock(AgentPolicyParameters.class);

    @BeforeClass
    public static void beforeClass() {
        Identifier identifier = new Identifier();
        identifier.setKind(IdentifierEnvs.HOST);
        AgentInfo.getInstance().setIdentifier(identifier);
        AgentInfo.getInstance().generateAppInfo(collectorConfig);
        AgentInfo.getInstance().initialiseHC();

        Mockito.doReturn(true).when(mode).getEnabled();

        Mockito.doReturn(true).when(blocking).getEnabled();

        Mockito.doReturn(mode).when(policy).getProtectionMode();
        Mockito.doReturn(blocking).when(mode).getApiBlocking();

        HashSet<String> set = new HashSet<>(); set.add("api");
        Mockito.doReturn(set).when(parameters).getAllowedApis();

        AgentUtils.getInstance().setAgentPolicy(policy);
        AgentUtils.getInstance().setAgentPolicyParameters(parameters);
    }

    @AfterClass
    public static void clean (){
        Mockito.clearInvocations(collectorConfig, parameters, policy, blocking, mode);
        Mockito.clearAllCaches();
    }
    @Test(expected = NullPointerException.class)
    public void registerOperationTest(){
        NewRelicSecurity.getAgent().registerOperation(Mockito.mock(FileOperation.class));
    }

    @Test
    public void registerOperation1Test(){
        try(MockedStatic<NewRelicSecurity> nrMock = Mockito.mockStatic(NewRelicSecurity.class, Answers.RETURNS_DEEP_STUBS)){
            SecurityMetaData metaData = Mockito.mock(SecurityMetaData.class);

            doReturn(Mockito.mock(HttpRequest.class)).when(metaData).getRequest();
            doReturn(Mockito.mock(HttpResponse.class)).when(metaData).getResponse();

            AgentMetaData agentMetaData = Mockito.mock(AgentMetaData.class);
            doReturn(Thread.currentThread().getStackTrace()).when(agentMetaData).getServiceTrace();
            doReturn(Mockito.mock(K2RequestIdentifier.class)).when(metaData).getFuzzRequestIdentifier();

            doReturn(agentMetaData).when(metaData).getMetaData();
            nrMock.when(() -> NewRelicSecurity.getAgent().getSecurityMetaData()).thenReturn(metaData);

            FileOperation operation = Mockito.mock(FileOperation.class);

            UserClassEntity entity = new UserClassEntity();
            entity.setUserClassElement(Thread.currentThread().getStackTrace()[1]);
            doReturn(entity).when(operation).getUserClassEntity();
            doReturn(VulnerabilityCaseType.FILE_OPERATION).when(operation).getCaseType();
            doReturn(Thread.currentThread().getStackTrace()).when(operation).getStackTrace();
            doReturn("api").when(operation).getApiID();
            doReturn("method").when(operation).getSourceMethod();

            Agent.getInstance().registerOperation(operation);

            Mockito.verify(operation, atLeastOnce()).getUserClassEntity();
            Mockito.verify(operation, atLeastOnce()).getCaseType();
            Mockito.verify(operation, atLeastOnce()).getStackTrace();
            Mockito.verify(operation, atLeastOnce()).getSourceMethod();
            Mockito.verify(operation, atLeastOnce()).getApiID();

            Mockito.clearInvocations(operation, agentMetaData, metaData);
            nrMock.reset();
            nrMock.clearInvocations();
        }
    }

    @Test(expected = NullPointerException.class)
    public void registerExitEventTest(){
        NewRelicSecurity.getAgent().registerExitEvent(Mockito.mock(FileOperation.class));
    }

    @Test
    public void registerExitEvent1Test() {
        try (MockedStatic<NewRelicSecurity> nrMock = Mockito.mockStatic(NewRelicSecurity.class, Answers.RETURNS_DEEP_STUBS)) {
            SecurityMetaData metaData = Mockito.mock(SecurityMetaData.class);
            doReturn(Mockito.mock(K2RequestIdentifier.class)).when(metaData).getFuzzRequestIdentifier();

            doReturn(Mockito.mock(HttpRequest.class)).when(metaData).getRequest();
            doReturn(Mockito.mock(HttpResponse.class)).when(metaData).getResponse();

            AgentMetaData agentMetaData = Mockito.mock(AgentMetaData.class);
            doReturn(Thread.currentThread().getStackTrace()).when(agentMetaData).getServiceTrace();
            doReturn(Mockito.mock(K2RequestIdentifier.class)).when(metaData).getFuzzRequestIdentifier();

            doReturn(agentMetaData).when(metaData).getMetaData();
            nrMock.when(() -> NewRelicSecurity.getAgent().getSecurityMetaData()).thenReturn(metaData);

            FileOperation operation = Mockito.mock(FileOperation.class);

            UserClassEntity entity = new UserClassEntity();
            entity.setUserClassElement(Thread.currentThread().getStackTrace()[1]);
            doReturn(entity).when(operation).getUserClassEntity();
            doReturn(VulnerabilityCaseType.FILE_OPERATION).when(operation).getCaseType();
            doReturn(Thread.currentThread().getStackTrace()).when(operation).getStackTrace();
            doReturn("api").when(operation).getApiID();
            doReturn("method").when(operation).getSourceMethod();

            Agent.getInstance().registerExitEvent(operation);

            Mockito.verify(operation, atLeastOnce()).isEmpty();
            Mockito.clearInvocations(operation, agentMetaData, metaData);
            nrMock.reset();
            nrMock.clearInvocations();
        }
    }

    @Test
    public void getSecurityMetaData1Test(){
        try (MockedStatic<NewRelicSecurity> nrMock = Mockito.mockStatic(NewRelicSecurity.class, Answers.RETURNS_DEEP_STUBS)){
            nrMock.when(() -> NewRelicSecurity.getAgent().isSecurityActive()).thenReturn(true);

            Assert.assertNotNull(NewRelicSecurity.getAgent().getSecurityMetaData());
            nrMock.reset();
            nrMock.clearInvocations();
        }
    }

    @Test
    public void getSecurityMetaData2Test(){
        try (MockedStatic<NewRelic> nrMock = Mockito.mockStatic(NewRelic.class, Answers.RETURNS_DEEP_STUBS);
             MockedStatic<NewRelicSecurity> nrMock1 = Mockito.mockStatic(NewRelicSecurity.class, Answers.RETURNS_DEEP_STUBS)
        ){
            SecurityMetaData metaData = Mockito.mock(SecurityMetaData.class);
            nrMock.when(() -> NewRelic.getAgent().getTransaction().getSecurityMetaData()).thenReturn(metaData);

            nrMock1.when(() -> NewRelicSecurity.getAgent().isSecurityActive()).thenReturn(true);

            Assert.assertNotNull(NewRelicSecurity.getAgent().getSecurityMetaData());

            nrMock.reset();
            nrMock.clearInvocations();
            nrMock1.reset();
            nrMock1.clearInvocations();
        }
    }

    @Test
    public void isLowPriorityInstrumentationEnabledFalseTest(){
        // LowPriorityInstrumentation is disabled
        Assert.assertFalse(NewRelicSecurity.getAgent().isLowPriorityInstrumentationEnabled());
    }
    @Test
    public void isLowPriorityInstrumentationEnabledTrueTest(){
        // LowPriorityInstrumentation is enabled
        try (MockedStatic<NewRelic> nrMock = Mockito.mockStatic(NewRelic.class, Answers.RETURNS_DEEP_STUBS)){
            nrMock.when(NewRelic.getAgent().getConfig().getValue(eq(LowSeverityHelper.LOW_SEVERITY_HOOKS_ENABLED), any())).thenReturn(true);

            Assert.assertTrue(NewRelicSecurity.getAgent().isLowPriorityInstrumentationEnabled());
            nrMock.reset();
            nrMock.clearInvocations();
        }
    }
}
