package com.newrelic.api.agent.security.instrumentation.helpers;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.schema.HttpRequest;
import com.newrelic.api.agent.security.schema.SecurityMetaData;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Answers;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

public class GenericHelperTest {
    private final String nrSecCustomAttrName = "CUSTOM_ATTRIBUTE";
    private final int hashCode = 0;

    @Test
    public void skipExistsEventTest() {
        Assertions.assertFalse(GenericHelper.skipExistsEvent());
    }

    @Test
    public void skipExistsEvent1Test() {
        MockedStatic<NewRelicSecurity> nrMock = Mockito.mockStatic(NewRelicSecurity.class, Answers.RETURNS_DEEP_STUBS);
        try {
            nrMock.when(() -> NewRelicSecurity.getAgent().getCurrentPolicy().getVulnerabilityScan().getEnabled()).thenReturn(true);
            Assertions.assertTrue(GenericHelper.skipExistsEvent());
        } finally {
            GrpcHelperTest.clearMockitoInvocation(nrMock);
        }
    }

    @Test
    public void skipExistsEvent2Test() {
        MockedStatic<NewRelicSecurity> nrMock = Mockito.mockStatic(NewRelicSecurity.class, Answers.RETURNS_DEEP_STUBS);
        try {
            nrMock.when(() -> NewRelicSecurity.getAgent().getCurrentPolicy().getVulnerabilityScan().getEnabled()).thenReturn(false);
            nrMock.when(() -> NewRelicSecurity.getAgent().getCurrentPolicy().getVulnerabilityScan().getIastScan().getEnabled()).thenReturn(false);
            Assertions.assertTrue(GenericHelper.skipExistsEvent());
        } finally {
            GrpcHelperTest.clearMockitoInvocation(nrMock);
        }
    }

    @Test
    public void skipExistsEvent3Test() {
        MockedStatic<NewRelicSecurity> nrMock = Mockito.mockStatic(NewRelicSecurity.class, Answers.RETURNS_DEEP_STUBS);
        try {
            nrMock.when(() -> NewRelicSecurity.getAgent().getCurrentPolicy().getVulnerabilityScan().getEnabled()).thenReturn(true);
            nrMock.when(() -> NewRelicSecurity.getAgent().getCurrentPolicy().getVulnerabilityScan().getIastScan().getEnabled()).thenReturn(true);
            Assertions.assertFalse(GenericHelper.skipExistsEvent());
        } finally {
            GrpcHelperTest.clearMockitoInvocation(nrMock);
        }
    }

    @Test
    public void isLockAcquiredTest() {
        Assertions.assertFalse(GenericHelper.isLockAcquired(nrSecCustomAttrName));
    }

    @Test
    public void isLockAcquiredTest1() {
        String customAttribute = nrSecCustomAttrName + Thread.currentThread().getId() + hashCode;
        MockedStatic<NewRelicSecurity> nrMock = Mockito.mockStatic(NewRelicSecurity.class, Answers.RETURNS_DEEP_STUBS);
        try {
            nrMock.when(() -> NewRelicSecurity.isHookProcessingActive()).thenReturn(true);
            nrMock.when(() -> NewRelicSecurity.getAgent().getSecurityMetaData().getCustomAttribute(customAttribute, Boolean.class)).thenReturn(true);
            Assertions.assertTrue(GenericHelper.isLockAcquired(nrSecCustomAttrName));
        } finally {
            GrpcHelperTest.clearMockitoInvocation(nrMock);
        }
    }

    @Test
    public void acquireLockIfPossibleTest() {
        Assertions.assertFalse(GenericHelper.acquireLockIfPossible(nrSecCustomAttrName));
    }

    @Test
    public void acquireLockIfPossibleTest1() {
        String customAttribute = nrSecCustomAttrName + Thread.currentThread().getId() + hashCode;
        MockedStatic<NewRelicSecurity> nrMock = Mockito.mockStatic(NewRelicSecurity.class, Answers.RETURNS_DEEP_STUBS);
        try {
            nrMock.when(() -> NewRelicSecurity.isHookProcessingActive()).thenReturn(true);
            SecurityMetaData metaData = new SecurityMetaData();
            metaData.addCustomAttribute(customAttribute, true);
            nrMock.when(() -> NewRelicSecurity.getAgent().getSecurityMetaData()).thenReturn(metaData);

            Assertions.assertFalse(GenericHelper.acquireLockIfPossible(nrSecCustomAttrName));
            Assertions.assertTrue(GenericHelper.isLockAcquired(nrSecCustomAttrName));

            GenericHelper.releaseLock(nrSecCustomAttrName);
            Assertions.assertFalse(GenericHelper.isLockAcquired(nrSecCustomAttrName));

        } finally {
            GrpcHelperTest.clearMockitoInvocation(nrMock);
        }
    }

    @Test
    public void acquireLockIfPossibleTest2() {
        MockedStatic<NewRelicSecurity> nrMock = Mockito.mockStatic(NewRelicSecurity.class, Answers.RETURNS_DEEP_STUBS);
        try {
            nrMock.when(() -> NewRelicSecurity.isHookProcessingActive()).thenReturn(true);
            nrMock.when(() -> NewRelicSecurity.getAgent().getSecurityMetaData()).thenReturn(new SecurityMetaData());

            Assertions.assertTrue(GenericHelper.acquireLockIfPossible(nrSecCustomAttrName));
            Assertions.assertTrue(GenericHelper.isLockAcquired(nrSecCustomAttrName));

            GenericHelper.releaseLock(nrSecCustomAttrName);
            Assertions.assertFalse(GenericHelper.isLockAcquired(nrSecCustomAttrName));

        } finally {
            GrpcHelperTest.clearMockitoInvocation(nrMock);
        }
    }

    @Test
    public void acquireLockIfPossibleExceptionTest() {
        MockedStatic<NewRelicSecurity> nrMock = Mockito.mockStatic(NewRelicSecurity.class, Answers.RETURNS_DEEP_STUBS);
        try {
            nrMock.when(() -> NewRelicSecurity.isHookProcessingActive()).thenReturn(true);
            nrMock.when(() -> NewRelicSecurity.getAgent().getSecurityMetaData()).thenReturn(null);

            Assertions.assertFalse(GenericHelper.acquireLockIfPossible(null, nrSecCustomAttrName));
            Assertions.assertFalse(GenericHelper.isLockAcquired(nrSecCustomAttrName, hashCode));

        } finally {
            GrpcHelperTest.clearMockitoInvocation(nrMock);
        }
    }

    @Test
    public void acquireLockIfPossibleHashCodeTest() {
        Assertions.assertFalse(GenericHelper.acquireLockIfPossible(nrSecCustomAttrName, hashCode));
    }

    @Test
    public void acquireLockIfPossibleHashCodeTest1() {
        String customAttribute = nrSecCustomAttrName + Thread.currentThread().getId();
        MockedStatic<NewRelicSecurity> nrMock = Mockito.mockStatic(NewRelicSecurity.class, Answers.RETURNS_DEEP_STUBS);
        try {
            nrMock.when(() -> NewRelicSecurity.isHookProcessingActive()).thenReturn(true);
            SecurityMetaData metaData = new SecurityMetaData();
            metaData.addCustomAttribute(customAttribute, true);
            nrMock.when(() -> NewRelicSecurity.getAgent().getSecurityMetaData()).thenReturn(metaData);

            Assertions.assertTrue(GenericHelper.acquireLockIfPossible(nrSecCustomAttrName, hashCode));
            Assertions.assertTrue(GenericHelper.isLockAcquired(nrSecCustomAttrName, hashCode));

            GenericHelper.releaseLock(nrSecCustomAttrName, hashCode);
            Assertions.assertFalse(GenericHelper.isLockAcquired(nrSecCustomAttrName, hashCode));

        } finally {
            GrpcHelperTest.clearMockitoInvocation(nrMock);
        }
    }

    @Test
    public void acquireLockIfPossibleCaseTypeTest() {
        Assertions.assertFalse(GenericHelper.acquireLockIfPossible(null, nrSecCustomAttrName, hashCode));
    }

    @Test
    public void acquireLockIfPossibleCaseTypeTest1() {
        MockedStatic<NewRelicSecurity> nrMock = Mockito.mockStatic(NewRelicSecurity.class, Answers.RETURNS_DEEP_STUBS);
        try {
            nrMock.when(NewRelicSecurity::isHookProcessingActive).thenReturn(true);
            SecurityMetaData metaData = new SecurityMetaData();
            HttpRequest request = Mockito.mock(HttpRequest.class);
            Mockito.doReturn(false).when(request).isEmpty();
            metaData.setRequest(request);
            metaData.addCustomAttribute(nrSecCustomAttrName + Thread.currentThread().getId(), true);
            nrMock.when(() -> NewRelicSecurity.getAgent().getSecurityMetaData()).thenReturn(metaData);

            Assertions.assertTrue(GenericHelper.acquireLockIfPossible(VulnerabilityCaseType.FILE_OPERATION, nrSecCustomAttrName, hashCode));
            Assertions.assertTrue(GenericHelper.isLockAcquired(nrSecCustomAttrName, hashCode));

            GenericHelper.releaseLock(nrSecCustomAttrName, hashCode);
            Assertions.assertFalse(GenericHelper.isLockAcquired(nrSecCustomAttrName, hashCode));

        } finally {
            GrpcHelperTest.clearMockitoInvocation(nrMock);
        }
    }

    @Test
    public void acquireLockIfPossibleCaseTypeTest2() {
        MockedStatic<NewRelicSecurity> nrMock = Mockito.mockStatic(NewRelicSecurity.class, Answers.RETURNS_DEEP_STUBS);
        try {
            nrMock.when(NewRelicSecurity::isHookProcessingActive).thenReturn(true);
            SecurityMetaData metaData = new SecurityMetaData();
            HttpRequest request = Mockito.mock(HttpRequest.class);
            Mockito.doReturn(false).when(request).isEmpty();
            metaData.setRequest(request);
            metaData.addCustomAttribute(nrSecCustomAttrName + Thread.currentThread().getId(), true);
            nrMock.when(() -> NewRelicSecurity.getAgent().getSecurityMetaData()).thenReturn(metaData);

            Assertions.assertTrue(GenericHelper.acquireLockIfPossible(VulnerabilityCaseType.HASH, nrSecCustomAttrName, hashCode));
            Assertions.assertTrue(GenericHelper.isLockAcquired(nrSecCustomAttrName, hashCode));

            GenericHelper.releaseLock(nrSecCustomAttrName, hashCode);
            Assertions.assertFalse(GenericHelper.isLockAcquired(nrSecCustomAttrName, hashCode));

        } finally {
            GrpcHelperTest.clearMockitoInvocation(nrMock);
        }
    }

    @Test
    public void acquireLockIfPossibleCaseTypeTest3() {
        MockedStatic<NewRelicSecurity> nrMock = Mockito.mockStatic(NewRelicSecurity.class, Answers.RETURNS_DEEP_STUBS);
        try {
            nrMock.when(NewRelicSecurity::isHookProcessingActive).thenReturn(true);
            SecurityMetaData metaData = new SecurityMetaData();
            HttpRequest request = Mockito.mock(HttpRequest.class);
            Mockito.doReturn(false).when(request).isEmpty();
            metaData.setRequest(request);
            metaData.addCustomAttribute(nrSecCustomAttrName + Thread.currentThread().getId(), true);
            nrMock.when(() -> NewRelicSecurity.getAgent().getSecurityMetaData()).thenReturn(metaData);

            Assertions.assertTrue(GenericHelper.acquireLockIfPossible(VulnerabilityCaseType.NOSQL_DB_COMMAND, nrSecCustomAttrName, hashCode));
            Assertions.assertTrue(GenericHelper.isLockAcquired(nrSecCustomAttrName, hashCode));

            GenericHelper.releaseLock(nrSecCustomAttrName, hashCode);
            Assertions.assertFalse(GenericHelper.isLockAcquired(nrSecCustomAttrName, hashCode));

        } finally {
            GrpcHelperTest.clearMockitoInvocation(nrMock);
        }
    }

    @Test
    public void acquireLockIfPossibleCaseTypeTest4() {
        MockedStatic<NewRelicSecurity> nrMock = Mockito.mockStatic(NewRelicSecurity.class, Answers.RETURNS_DEEP_STUBS);
        try {
            nrMock.when(NewRelicSecurity::isHookProcessingActive).thenReturn(true);
            SecurityMetaData metaData = new SecurityMetaData();
            HttpRequest request = Mockito.mock(HttpRequest.class);
            Mockito.doReturn(false).when(request).isEmpty();
            metaData.setRequest(request);
            metaData.addCustomAttribute(nrSecCustomAttrName + Thread.currentThread().getId(), true);
            nrMock.when(() -> NewRelicSecurity.getAgent().getSecurityMetaData()).thenReturn(metaData);

            Assertions.assertTrue(GenericHelper.acquireLockIfPossible(VulnerabilityCaseType.XPATH, nrSecCustomAttrName, hashCode));
            Assertions.assertTrue(GenericHelper.isLockAcquired(nrSecCustomAttrName, hashCode));

            GenericHelper.releaseLock(nrSecCustomAttrName, hashCode);
            Assertions.assertFalse(GenericHelper.isLockAcquired(nrSecCustomAttrName, hashCode));

        } finally {
            GrpcHelperTest.clearMockitoInvocation(nrMock);
        }
    }
}
