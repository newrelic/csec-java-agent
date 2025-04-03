package com.newrelic.agent.security.instrumentator.utils;

import com.newrelic.api.agent.NewRelic;
import com.newrelic.api.agent.security.schema.policy.AgentPolicy;
import org.junit.Assert;
import org.junit.Test;
import org.mockito.Answers;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;

public class AgentUtilsTest {

    @Test
    public void applyPolicyOverrideIfApplicable(){
        Assert.assertFalse(AgentUtils.getInstance().applyPolicyOverrideIfApplicable());
    }

    @Test
    public void applyPolicyOverrideIfApplicable1(){
        try (MockedStatic<NewRelic> nrMock = Mockito.mockStatic(NewRelic.class, Answers.RETURNS_DEEP_STUBS)){
            nrMock.when(NewRelic.getAgent().getConfig().getValue(eq(INRSettingsKey.SECURITY_POLICY_ENFORCE), any())).thenReturn(false);

            Assert.assertFalse(AgentUtils.getInstance().applyPolicyOverrideIfApplicable());
            Assert.assertFalse(AgentUtils.getInstance().isPolicyOverridden());


            nrMock.reset();
            nrMock.clearInvocations();
        }
    }
    @Test
    public void applyPolicyOverrideIfApplicable2(){
        try (MockedStatic<NewRelic> nrMock = Mockito.mockStatic(NewRelic.class, Answers.RETURNS_DEEP_STUBS)){
            nrMock.when(NewRelic.getAgent().getConfig().getValue(eq(INRSettingsKey.SECURITY_POLICY_ENFORCE), any())).thenReturn(false);
            nrMock.when(NewRelic.getAgent().getConfig().getValue(INRSettingsKey.SECURITY_POLICY_VULNERABILITY_SCAN_ENABLE)).thenReturn(false);
            nrMock.when(NewRelic.getAgent().getConfig().getValue(INRSettingsKey.SECURITY_POLICY_VULNERABILITY_SCAN_IAST_SCAN_ENABLE)).thenReturn(false);
            nrMock.when(NewRelic.getAgent().getConfig().getValue(INRSettingsKey.SECURITY_POLICY_VULNERABILITY_SCAN_IAST_SCAN_PROBING_INTERVAL)).thenReturn(1);
            nrMock.when(NewRelic.getAgent().getConfig().getValue(INRSettingsKey.SECURITY_POLICY_VULNERABILITY_SCAN_IAST_SCAN_PROBING_BATCH_SIZE)).thenReturn(1);
            nrMock.when(NewRelic.getAgent().getConfig().getValue(INRSettingsKey.SECURITY_POLICY_PROTECTION_MODE_ENABLE)).thenReturn(false);
            nrMock.when(NewRelic.getAgent().getConfig().getValue(INRSettingsKey.SECURITY_POLICY_PROTECTION_MODE_IP_BLOCKING_ENABLE)).thenReturn(false);
            nrMock.when(NewRelic.getAgent().getConfig().getValue(INRSettingsKey.SECURITY_POLICY_PROTECTION_MODE_IP_BLOCKING_ATTACKER_IP_BLOCKING)).thenReturn(false);
            nrMock.when(NewRelic.getAgent().getConfig().getValue(INRSettingsKey.SECURITY_POLICY_PROTECTION_MODE_IP_BLOCKING_IP_DETECT_VIA_XFF)).thenReturn(false);
            nrMock.when(NewRelic.getAgent().getConfig().getValue(INRSettingsKey.SECURITY_POLICY_PROTECTION_MODE_API_BLOCKING_ENABLE)).thenReturn(false);
            nrMock.when(NewRelic.getAgent().getConfig().getValue(INRSettingsKey.SECURITY_POLICY_PROTECTION_MODE_API_BLOCKING_PROTECT_ALL_APIS)).thenReturn(false);
            nrMock.when(NewRelic.getAgent().getConfig().getValue(INRSettingsKey.SECURITY_POLICY_PROTECTION_MODE_API_BLOCKING_PROTECT_KNOWN_VULNERABLE_APIS)).thenReturn(false);
            nrMock.when(NewRelic.getAgent().getConfig().getValue(INRSettingsKey.SECURITY_POLICY_PROTECTION_MODE_API_BLOCKING_PROTECT_ATTACKED_APIS)).thenReturn(false);

            Assert.assertFalse(AgentUtils.getInstance().applyPolicyOverrideIfApplicable());
            Assert.assertFalse(AgentUtils.getInstance().isPolicyOverridden());

            AgentPolicy policy = AgentUtils.getInstance().getAgentPolicy();
            Assert.assertTrue(policy.getVulnerabilityScan().getEnabled());
            Assert.assertTrue(policy.getVulnerabilityScan().getIastScan().getEnabled());
//            Assert.assertEquals(5, policy.getVulnerabilityScan().getIastScan().getProbing().getInterval().intValue());
//            Assert.assertEquals(50, policy.getVulnerabilityScan().getIastScan().getProbing().getBatchSize().intValue());
//            Assert.assertFalse(policy.getProtectionMode().getEnabled());
//            Assert.assertFalse(policy.getProtectionMode().getIpBlocking().getEnabled());
//            Assert.assertFalse(policy.getProtectionMode().getIpBlocking().getAttackerIpBlocking());
//            Assert.assertFalse(policy.getProtectionMode().getIpBlocking().getIpDetectViaXFF());
//            Assert.assertFalse(policy.getProtectionMode().getApiBlocking().getProtectAllApis());
//            Assert.assertFalse(policy.getProtectionMode().getApiBlocking().getProtectKnownVulnerableApis());
//            Assert.assertFalse(policy.getProtectionMode().getApiBlocking().getProtectAttackedApis());

            nrMock.reset();
            nrMock.clearInvocations();
        }
    }
    @Test
    public void applyPolicyOverrideIfApplicable3(){
//        try (MockedStatic<NewRelic> nrMock = Mockito.mockStatic(NewRelic.class, Answers.RETURNS_DEEP_STUBS)){
//            nrMock.when(NewRelic.getAgent().getConfig().getValue(eq(INRSettingsKey.SECURITY_POLICY_ENFORCE), any())).thenReturn(true);
//            nrMock.when(NewRelic.getAgent().getConfig().getValue(INRSettingsKey.SECURITY_POLICY_VULNERABILITY_SCAN_ENABLE)).thenReturn(true);
//            nrMock.when(NewRelic.getAgent().getConfig().getValue(INRSettingsKey.SECURITY_POLICY_VULNERABILITY_SCAN_IAST_SCAN_ENABLE)).thenReturn(true);
//            nrMock.when(NewRelic.getAgent().getConfig().getValue(INRSettingsKey.SECURITY_POLICY_VULNERABILITY_SCAN_IAST_SCAN_PROBING_INTERVAL)).thenReturn(10);
//            nrMock.when(NewRelic.getAgent().getConfig().getValue(INRSettingsKey.SECURITY_POLICY_VULNERABILITY_SCAN_IAST_SCAN_PROBING_BATCH_SIZE)).thenReturn(10);
//            nrMock.when(NewRelic.getAgent().getConfig().getValue(INRSettingsKey.SECURITY_POLICY_PROTECTION_MODE_ENABLE)).thenReturn(true);
//            nrMock.when(NewRelic.getAgent().getConfig().getValue(INRSettingsKey.SECURITY_POLICY_PROTECTION_MODE_IP_BLOCKING_ENABLE)).thenReturn(true);
//            nrMock.when(NewRelic.getAgent().getConfig().getValue(INRSettingsKey.SECURITY_POLICY_PROTECTION_MODE_IP_BLOCKING_ATTACKER_IP_BLOCKING)).thenReturn(true);
//            nrMock.when(NewRelic.getAgent().getConfig().getValue(INRSettingsKey.SECURITY_POLICY_PROTECTION_MODE_IP_BLOCKING_IP_DETECT_VIA_XFF)).thenReturn(true);
//            nrMock.when(NewRelic.getAgent().getConfig().getValue(INRSettingsKey.SECURITY_POLICY_PROTECTION_MODE_API_BLOCKING_ENABLE)).thenReturn(true);
//            nrMock.when(NewRelic.getAgent().getConfig().getValue(INRSettingsKey.SECURITY_POLICY_PROTECTION_MODE_API_BLOCKING_PROTECT_ALL_APIS)).thenReturn(true);
//            nrMock.when(NewRelic.getAgent().getConfig().getValue(INRSettingsKey.SECURITY_POLICY_PROTECTION_MODE_API_BLOCKING_PROTECT_KNOWN_VULNERABLE_APIS)).thenReturn(true);
//            nrMock.when(NewRelic.getAgent().getConfig().getValue(INRSettingsKey.SECURITY_POLICY_PROTECTION_MODE_API_BLOCKING_PROTECT_ATTACKED_APIS)).thenReturn(true);
//
//            Assert.assertFalse(AgentUtils.getInstance().applyPolicyOverrideIfApplicable());
//            Assert.assertTrue(AgentUtils.getInstance().isPolicyOverridden());
//
//            AgentPolicy policy = AgentUtils.getInstance().getAgentPolicy();
//            Assert.assertTrue(policy.getVulnerabilityScan().getEnabled());
//            Assert.assertTrue(policy.getVulnerabilityScan().getIastScan().getEnabled());
//            Assert.assertEquals(10, policy.getVulnerabilityScan().getIastScan().getProbing().getInterval().intValue());
//            Assert.assertEquals(10, policy.getVulnerabilityScan().getIastScan().getProbing().getBatchSize().intValue());
//            Assert.assertTrue(policy.getProtectionMode().getEnabled());
//            Assert.assertTrue(policy.getProtectionMode().getIpBlocking().getEnabled());
//            Assert.assertTrue(policy.getProtectionMode().getIpBlocking().getAttackerIpBlocking());
//            Assert.assertTrue(policy.getProtectionMode().getIpBlocking().getIpDetectViaXFF());
//            Assert.assertTrue(policy.getProtectionMode().getApiBlocking().getProtectAllApis());
//            Assert.assertTrue(policy.getProtectionMode().getApiBlocking().getProtectKnownVulnerableApis());
//            Assert.assertTrue(policy.getProtectionMode().getApiBlocking().getProtectAttackedApis());
//
//            nrMock.reset();
//            nrMock.clearInvocations();
//        }
    }

    @Test
    public void applyPolicy() {
//        Assert.assertTrue(AgentUtils.applyPolicy(new AgentPolicy()));
    }
}
