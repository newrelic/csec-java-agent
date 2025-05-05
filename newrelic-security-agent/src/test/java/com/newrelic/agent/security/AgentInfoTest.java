package com.newrelic.agent.security;

import com.newrelic.agent.security.instrumentator.utils.INRSettingsKey;
import com.newrelic.agent.security.intcodeagent.models.collectorconfig.CollectorConfig;
import com.newrelic.agent.security.intcodeagent.models.javaagent.ApplicationInfoBean;
import com.newrelic.agent.security.intcodeagent.models.javaagent.EventStats;
import com.newrelic.agent.security.intcodeagent.models.javaagent.Identifier;
import com.newrelic.agent.security.intcodeagent.models.javaagent.IdentifierEnvs;
import com.newrelic.agent.security.intcodeagent.models.javaagent.JAHealthCheck;
import com.newrelic.agent.security.util.IUtilConstants;
import com.newrelic.api.agent.NewRelic;
import org.junit.Assert;
import org.junit.BeforeClass;

import org.junit.Test;
import org.mockito.Mockito;

import java.util.Collections;
import java.util.Properties;
import java.util.concurrent.atomic.AtomicInteger;

public class AgentInfoTest {
    @BeforeClass
    public static void setUp() {
        Identifier identifier = new Identifier();
        identifier.setKind(IdentifierEnvs.HOST);
        AgentInfo.getInstance().setIdentifier(identifier);
    }

    @Test
    
    public void generateAppInfo() {
//        ApplicationInfoBean appInfoBean = AgentInfo.getInstance().generateAppInfo(Mockito.mock(CollectorConfig.class));
//        Assert.assertEquals(AgentInfo.getInstance().getApplicationUUID(), appInfoBean.getApplicationUUID());
//        Assert.assertEquals("STATIC", appInfoBean.getAgentAttachmentType());
//        Assert.assertEquals(AgentInfo.getInstance().getVMPID(), appInfoBean.getPid());
//        Assert.assertEquals("JAVA", appInfoBean.getCollectorType());
//        Assert.assertEquals("Java", appInfoBean.getLanguage());
    }

    @Test
    public void initializeHC() {
//        AgentInfo.getInstance().generateAppInfo(Mockito.mock(CollectorConfig.class));
//        AgentInfo.getInstance().initialiseHC();
//        JAHealthCheck jaHealthCheck = AgentInfo.getInstance().getJaHealthCheck();
        Properties properties = new Properties();
        //default application_logging is true
        properties.put("newrelic.config.application_logging.enabled", "false");
        System.setProperty("newrelic.config.security.scan_controllers.scan_instance_count", "1");
        System.out.println("config found ---" + NewRelic.getAgent().getConfig().getValue(IUtilConstants.IAST_SCAN_INSTANCE_COUNT));
//        assertion(jaHealthCheck, new AtomicInteger(0), new EventStats());
    }

    @Test
    public void isAgentActive() {
        Assert.assertFalse(AgentInfo.getInstance().isAgentActive());
    }
//    @Test
//    public void initializeHC1() {
//        AgentInfo.getInstance().generateAppInfo(Mockito.mock(CollectorConfig.class));
//        AgentInfo.getInstance().initialiseHC();
//        JAHealthCheck jaHealthCheck = AgentInfo.getInstance().getJaHealthCheck();
//        jaHealthCheck.incrementInvokedHookCount();
//        jaHealthCheck.incrementDropCount();
//        jaHealthCheck.incrementProcessedCount();
//        jaHealthCheck.incrementEventSentCount();
//        jaHealthCheck.incrementHttpRequestCount();
//        jaHealthCheck.incrementExitEventSentCount();
//        jaHealthCheck.incrementEventRejectionCount();
//        jaHealthCheck.incrementEventProcessingErrorCount();
//        jaHealthCheck.incrementEventSendRejectionCount();
//        jaHealthCheck.incrementEventSendErrorCount();
//        assertion(jaHealthCheck, new AtomicInteger(1), new EventStats());
//
//        // resetting the JAHealthCheck
//        jaHealthCheck.reset();
//        assertion(jaHealthCheck, new AtomicInteger(0), new EventStats());
//    }

//    private void assertion(JAHealthCheck jaHealthCheck, AtomicInteger atomicInteger, EventStats expectedEventStats) {
//        Assert.assertEquals(AgentInfo.getInstance().getApplicationUUID(), jaHealthCheck.getApplicationUUID());
//        Assert.assertEquals(atomicInteger.get(), jaHealthCheck.getInvokedHookCount());
//        Assert.assertEquals(atomicInteger.get(), jaHealthCheck.getEventDropCount().intValue());
//        Assert.assertEquals(atomicInteger.get(), jaHealthCheck.getEventProcessed().intValue());
//        Assert.assertEquals(atomicInteger.get(), jaHealthCheck.getEventSentCount().get());
//        Assert.assertEquals(atomicInteger.get(), jaHealthCheck.getHttpRequestCount().get());
//        Assert.assertEquals(atomicInteger.get(), jaHealthCheck.getExitEventSentCount().get());
//        Assert.assertEquals(atomicInteger.get(), jaHealthCheck.getEventRejectionCount().get());
//        Assert.assertEquals(atomicInteger.get(), jaHealthCheck.getEventProcessingErrorCount().get());
//        Assert.assertEquals(atomicInteger.get(), jaHealthCheck.getEventSendRejectionCount().get());
//        Assert.assertEquals(atomicInteger.get(), jaHealthCheck.getEventSendErrorCount().get());
//
//        assertEventStats(expectedEventStats, jaHealthCheck.getExitEventStats());
//        assertEventStats(expectedEventStats, jaHealthCheck.getIastEventStats());
//        assertEventStats(expectedEventStats, jaHealthCheck.getRaspEventStats());
//        Assert.assertEquals("HOST", jaHealthCheck.getKind().name());
//    }

//    private void assertEventStats(EventStats expectedEventStats, EventStats actualEventStats) {
//        Assert.assertSame(expectedEventStats.getErrorCount().get(), actualEventStats.getErrorCount().get());
//        Assert.assertSame(expectedEventStats.getProcessed().get(), actualEventStats.getProcessed().get());
//        Assert.assertSame(expectedEventStats.getSent().get(), actualEventStats.getSent().get());
//        Assert.assertSame(expectedEventStats.getRejected().get(), actualEventStats.getRejected().get());
//    }
}
