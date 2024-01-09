package com.newrelic.api.agent.security.instrumentation.helpers;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.JDBCVendor;
import com.newrelic.api.agent.security.schema.R2DBCVendor;
import com.newrelic.api.agent.security.schema.SecurityMetaData;
import com.newrelic.api.agent.security.schema.StringUtils;
import com.newrelic.api.agent.security.schema.operation.SQLOperation;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Answers;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import java.util.Collections;
import java.util.Map;

import static com.newrelic.api.agent.security.instrumentation.helpers.R2dbcHelper.NR_SEC_CUSTOM_ATTRIB_NAME;

public class R2dbcHelperTest {
    private final String SQL = "select * from users";
    public final String CLASS_NAME = "className";
    public final String METHOD_NAME = "methodName";
    @Test
    public void skipExistsEvent() {
        Assertions.assertTrue(R2dbcHelper.skipExistsEvent());
    }
    @Test
    public void skipExistsEventTest1(){
        try (MockedStatic<NewRelicSecurity> nrMock = Mockito.mockStatic(NewRelicSecurity.class, Answers.RETURNS_DEEP_STUBS)){
            nrMock.when(() -> NewRelicSecurity.getAgent().getCurrentPolicy().getVulnerabilityScan().getEnabled()).thenReturn(true);
            Assertions.assertTrue(R2dbcHelper.skipExistsEvent());
            nrMock.clearInvocations();
            nrMock.reset();
        }
    }
    @Test
    public void skipExistsEventTest2(){
        try (MockedStatic<NewRelicSecurity> nrMock = Mockito.mockStatic(NewRelicSecurity.class, Answers.RETURNS_DEEP_STUBS)){
            nrMock.when(() -> NewRelicSecurity.getAgent().getCurrentPolicy().getVulnerabilityScan().getEnabled()).thenReturn(false);
            nrMock.when(() -> NewRelicSecurity.getAgent().getCurrentPolicy().getVulnerabilityScan().getIastScan().getEnabled()).thenReturn(false);
            Assertions.assertTrue(R2dbcHelper.skipExistsEvent());
            nrMock.clearInvocations();
            nrMock.reset();
        }
    }
    @Test
    public void skipExistsEventTest3(){
        try (MockedStatic<NewRelicSecurity> nrMock = Mockito.mockStatic(NewRelicSecurity.class, Answers.RETURNS_DEEP_STUBS)){
            nrMock.when(() -> NewRelicSecurity.getAgent().getCurrentPolicy().getVulnerabilityScan().getEnabled()).thenReturn(true);
            nrMock.when(() -> NewRelicSecurity.getAgent().getCurrentPolicy().getVulnerabilityScan().getIastScan().getEnabled()).thenReturn(true);
            Assertions.assertFalse(R2dbcHelper.skipExistsEvent());
            nrMock.clearInvocations();
            nrMock.reset();
        }
    }

    @Test
    public void isLockAcquiredTest(){
        Assertions.assertFalse(R2dbcHelper.isLockAcquired());
    }
    @Test
    public void isLockAcquiredTest1(){
        String customAttribute = NR_SEC_CUSTOM_ATTRIB_NAME + Thread.currentThread().getId();
        try (MockedStatic<NewRelicSecurity> nrMock = Mockito.mockStatic(NewRelicSecurity.class, Answers.RETURNS_DEEP_STUBS)){
            nrMock.when(() -> NewRelicSecurity.isHookProcessingActive()).thenReturn(true);
            nrMock.when(() -> NewRelicSecurity.getAgent().getSecurityMetaData().getCustomAttribute(customAttribute, Boolean.class)).thenReturn(true);
            Assertions.assertTrue(R2dbcHelper.isLockAcquired());
            nrMock.clearInvocations();
            nrMock.reset();
        }
    }

    @Test
    public void acquireLockIfPossibleTest(){
        Assertions.assertFalse(R2dbcHelper.acquireLockIfPossible());
    }
    @Test
    public void acquireLockIfPossibleTest1(){
        String customAttribute = NR_SEC_CUSTOM_ATTRIB_NAME + Thread.currentThread().getId();
        try (MockedStatic<NewRelicSecurity> nrMock = Mockito.mockStatic(NewRelicSecurity.class, Answers.RETURNS_DEEP_STUBS)){
            nrMock.when(() -> NewRelicSecurity.isHookProcessingActive()).thenReturn(true);
            SecurityMetaData metaData = new SecurityMetaData();
            metaData.addCustomAttribute(customAttribute, true);
            nrMock.when(() -> NewRelicSecurity.getAgent().getSecurityMetaData()).thenReturn(metaData);
            Assertions.assertFalse(R2dbcHelper.acquireLockIfPossible());
            nrMock.clearInvocations();
            nrMock.reset();
        }
    }
    @Test
    public void acquireLockIfPossibleTest2(){
        try (MockedStatic<NewRelicSecurity> nrMock = Mockito.mockStatic(NewRelicSecurity.class, Answers.RETURNS_DEEP_STUBS)){
            nrMock.when(() -> NewRelicSecurity.isHookProcessingActive()).thenReturn(true);
            nrMock.when(() -> NewRelicSecurity.getAgent().getSecurityMetaData()).thenReturn(new SecurityMetaData());
            Assertions.assertTrue(R2dbcHelper.acquireLockIfPossible());
            nrMock.clearInvocations();
            nrMock.reset();
        }
    }
    @Test
    public void preprocessSecurityHookNullTest(){
        Assertions.assertNull(R2dbcHelper.preprocessSecurityHook(SQL, METHOD_NAME, CLASS_NAME, null, false));
    }
    @Test
    public void preprocessSecurityHookNullTest1(){
        try (MockedStatic<NewRelicSecurity> nrMock = Mockito.mockStatic(NewRelicSecurity.class, Answers.RETURNS_DEEP_STUBS)) {
            nrMock.when(() -> NewRelicSecurity.isHookProcessingActive()).thenReturn(true);
            nrMock.when(() -> NewRelicSecurity.getAgent().getSecurityMetaData()).thenReturn(null);
            Assertions.assertNull(R2dbcHelper.preprocessSecurityHook(SQL, METHOD_NAME, CLASS_NAME, null, false));
            nrMock.clearInvocations();
            nrMock.reset();
        }
    }
    @Test
    public void preprocessSecurityHookNullTest2(){
        try (MockedStatic<NewRelicSecurity> nrMock = Mockito.mockStatic(NewRelicSecurity.class, Answers.RETURNS_DEEP_STUBS)) {
            nrMock.when(() -> NewRelicSecurity.isHookProcessingActive()).thenReturn(true);
            Assertions.assertNull(R2dbcHelper.preprocessSecurityHook(null, METHOD_NAME, CLASS_NAME, null, false));
            nrMock.clearInvocations();
            nrMock.reset();
        }
    }
    @Test
    public void preprocessSecurityHookNullTest3(){
        try (MockedStatic<NewRelicSecurity> nrMock = Mockito.mockStatic(NewRelicSecurity.class, Answers.RETURNS_DEEP_STUBS)) {
            nrMock.when(() -> NewRelicSecurity.isHookProcessingActive()).thenReturn(true);
            Assertions.assertNull(R2dbcHelper.preprocessSecurityHook(StringUtils.EMPTY, METHOD_NAME, CLASS_NAME, null, false));
            nrMock.clearInvocations();
            nrMock.reset();
        }
    }
    @Test
    public void preprocessSecurityHookNullTest4(){
        try (MockedStatic<NewRelicSecurity> nrMock = Mockito.mockStatic(NewRelicSecurity.class, Answers.RETURNS_DEEP_STUBS)) {
            nrMock.when(() -> NewRelicSecurity.isHookProcessingActive()).thenReturn(true);
            Assertions.assertNull(R2dbcHelper.preprocessSecurityHook("  ", METHOD_NAME, CLASS_NAME, null, false));
            nrMock.clearInvocations();
            nrMock.reset();
        }
    }
    @Test
    public void preprocessSecurityHookTest(){
        try (MockedStatic<NewRelicSecurity> nrMock = Mockito.mockStatic(NewRelicSecurity.class, Answers.RETURNS_DEEP_STUBS)) {
            nrMock.when(() -> NewRelicSecurity.isHookProcessingActive()).thenReturn(true);
            Map<String, String> param = null;
            boolean isPrepared = false;
            assertions(R2dbcHelper.preprocessSecurityHook(SQL, METHOD_NAME, CLASS_NAME, param, isPrepared), param, isPrepared, JdbcHelper.UNKNOWN);
            nrMock.clearInvocations();
            nrMock.reset();
        }
    }
    @Test
    public void preprocessSecurityHookTest1(){
        try (MockedStatic<NewRelicSecurity> nrMock = Mockito.mockStatic(NewRelicSecurity.class, Answers.RETURNS_DEEP_STUBS)) {
            nrMock.when(() -> NewRelicSecurity.isHookProcessingActive()).thenReturn(true);
            nrMock.when(() -> NewRelicSecurity.getAgent().getSecurityMetaData()
                    .getCustomAttribute(R2DBCVendor.META_CONST_R2DBC_VENDOR, String.class)).thenReturn(JDBCVendor.MYSQL);
            Map<String, String> param = Collections.emptyMap();
            boolean isPrepared = true;
            assertions(R2dbcHelper.preprocessSecurityHook(SQL, METHOD_NAME, CLASS_NAME, param, isPrepared), param, isPrepared, JDBCVendor.MYSQL);
            nrMock.clearInvocations();
            nrMock.reset();
        }
    }
    @Test
    public void preprocessSecurityHookTest2(){
        try (MockedStatic<NewRelicSecurity> nrMock = Mockito.mockStatic(NewRelicSecurity.class, Answers.RETURNS_DEEP_STUBS)) {
            nrMock.when(() -> NewRelicSecurity.isHookProcessingActive()).thenReturn(true);
            nrMock.when(() -> NewRelicSecurity.getAgent().getSecurityMetaData()
                    .getCustomAttribute(R2DBCVendor.META_CONST_R2DBC_VENDOR, String.class)).thenReturn(JDBCVendor.MYSQL);
            Map<String, String> param = Collections.singletonMap("key", "val");
            boolean isPrepared = true;
            assertions(R2dbcHelper.preprocessSecurityHook(SQL, METHOD_NAME, CLASS_NAME, param, isPrepared), param, isPrepared, JDBCVendor.MYSQL);
            nrMock.clearInvocations();
            nrMock.reset();
        }
    }

    private void assertions(AbstractOperation actualOp, Map<String, String> expectedParams, boolean expectedIsPrepared, String expectedDBName){
        Assertions.assertNotNull(actualOp);
        Assertions.assertTrue(actualOp instanceof SQLOperation);
        SQLOperation op = (SQLOperation) actualOp;
        Assertions.assertEquals(SQL, op.getQuery());
        Assertions.assertEquals(CLASS_NAME, op.getClassName());
        Assertions.assertEquals(METHOD_NAME, op.getMethodName());
        Assertions.assertEquals(expectedParams, op.getParams());
        Assertions.assertEquals(expectedIsPrepared, op.isPreparedCall());
        Assertions.assertEquals(expectedDBName, op.getDbName());
    }
}
