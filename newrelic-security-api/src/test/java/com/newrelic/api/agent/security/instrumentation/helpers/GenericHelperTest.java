package com.newrelic.api.agent.security.instrumentation.helpers;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.schema.SecurityMetaData;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Answers;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

public class GenericHelperTest {
    private final String nrSecCustomAttrName = "CUSTOM_ATTRIBUTE";
    private final int hashCode = 0;

    @Test
    public void skipExistsEvent() {
        Assertions.assertTrue(GenericHelper.skipExistsEvent());
    }
    @Test
    public void skipExistsEvent1() {
        try (MockedStatic<NewRelicSecurity> nrMock = Mockito.mockStatic(NewRelicSecurity.class, Answers.RETURNS_DEEP_STUBS)){
            nrMock.when(() -> NewRelicSecurity.getAgent().getCurrentPolicy().getVulnerabilityScan().getEnabled()).thenReturn(true);
            Assertions.assertTrue(GenericHelper.skipExistsEvent());
            nrMock.clearInvocations();
            nrMock.reset();
        }
    }
    @Test
    public void skipExistsEvent2() {
        try (MockedStatic<NewRelicSecurity> nrMock = Mockito.mockStatic(NewRelicSecurity.class, Answers.RETURNS_DEEP_STUBS)){
            nrMock.when(() -> NewRelicSecurity.getAgent().getCurrentPolicy().getVulnerabilityScan().getEnabled()).thenReturn(false);
            nrMock.when(() -> NewRelicSecurity.getAgent().getCurrentPolicy().getVulnerabilityScan().getIastScan().getEnabled()).thenReturn(false);
            Assertions.assertTrue(GenericHelper.skipExistsEvent());
            nrMock.clearInvocations();
            nrMock.reset();
        }
    }
    @Test
    public void skipExistsEvent3() {
        try (MockedStatic<NewRelicSecurity> nrMock = Mockito.mockStatic(NewRelicSecurity.class, Answers.RETURNS_DEEP_STUBS)){
            nrMock.when(() -> NewRelicSecurity.getAgent().getCurrentPolicy().getVulnerabilityScan().getEnabled()).thenReturn(true);
            nrMock.when(() -> NewRelicSecurity.getAgent().getCurrentPolicy().getVulnerabilityScan().getIastScan().getEnabled()).thenReturn(true);
            Assertions.assertFalse(GenericHelper.skipExistsEvent());
            nrMock.clearInvocations();
            nrMock.reset();
        }
    }
    @Test
    public void isLockAcquired(){
        Assertions.assertFalse(GenericHelper.isLockAcquired(nrSecCustomAttrName));
    }
    @Test
    public void isLockAcquired1() {
        String customAttribute = nrSecCustomAttrName + Thread.currentThread().getId() + hashCode;
        try (MockedStatic<NewRelicSecurity> nrMock = Mockito.mockStatic(NewRelicSecurity.class, Answers.RETURNS_DEEP_STUBS)){
            nrMock.when(() -> NewRelicSecurity.isHookProcessingActive()).thenReturn(true);
            nrMock.when(() -> NewRelicSecurity.getAgent().getSecurityMetaData().getCustomAttribute(customAttribute, Boolean.class)).thenReturn(true);
            Assertions.assertTrue(GenericHelper.isLockAcquired(nrSecCustomAttrName));
            nrMock.clearInvocations();
            nrMock.reset();
        }
    }
    @Test
    public void acquireLockIfPossible(){
        Assertions.assertFalse(GenericHelper.acquireLockIfPossible(nrSecCustomAttrName));
    }
    @Test
    public void acquireLockIfPossible1() {
        String customAttribute = nrSecCustomAttrName + Thread.currentThread().getId() + hashCode;
        try (MockedStatic<NewRelicSecurity> nrMock = Mockito.mockStatic(NewRelicSecurity.class, Answers.RETURNS_DEEP_STUBS)){
            nrMock.when(() -> NewRelicSecurity.isHookProcessingActive()).thenReturn(true);
            SecurityMetaData metaData = new SecurityMetaData();
            metaData.addCustomAttribute(customAttribute, true);
            nrMock.when(() -> NewRelicSecurity.getAgent().getSecurityMetaData()).thenReturn(metaData);
            Assertions.assertFalse(GenericHelper.acquireLockIfPossible(nrSecCustomAttrName));
            nrMock.clearInvocations();
            nrMock.reset();
        }
    }
    @Test
    public void acquireLockIfPossible2() {
        try (MockedStatic<NewRelicSecurity> nrMock = Mockito.mockStatic(NewRelicSecurity.class, Answers.RETURNS_DEEP_STUBS)){
            nrMock.when(() -> NewRelicSecurity.isHookProcessingActive()).thenReturn(true);
            nrMock.when(() -> NewRelicSecurity.getAgent().getSecurityMetaData()).thenReturn(new SecurityMetaData());
            Assertions.assertTrue(GenericHelper.acquireLockIfPossible(nrSecCustomAttrName));
            nrMock.clearInvocations();
            nrMock.reset();
        }
    }
}
