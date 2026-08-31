package com.newrelic.api.agent.security.instrumentation.helpers;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.schema.JDBCVendor;
import com.newrelic.api.agent.security.schema.SecurityMetaData;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Answers;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import static com.newrelic.api.agent.security.instrumentation.helpers.JdbcHelper.NR_SEC_CUSTOM_ATTRIB_NAME;

public class JdbcHelperTest {
    @Test
    public void skipExistsEventTest() {
        Assertions.assertFalse(JdbcHelper.skipExistsEvent());
    }
    @Test
    public void skipExistsEventTest1() {
        try (MockedStatic<NewRelicSecurity> nrMock = Mockito.mockStatic(NewRelicSecurity.class, Answers.RETURNS_DEEP_STUBS)){
            nrMock.when(() -> NewRelicSecurity.getAgent().getCurrentPolicy().getVulnerabilityScan().getEnabled()).thenReturn(true);
            Assertions.assertTrue(JdbcHelper.skipExistsEvent());
            nrMock.clearInvocations();
            nrMock.reset();
        }
    }
    @Test
    public void skipExistsEventTest2() {
        try (MockedStatic<NewRelicSecurity> nrMock = Mockito.mockStatic(NewRelicSecurity.class, Answers.RETURNS_DEEP_STUBS)){
            nrMock.when(() -> NewRelicSecurity.getAgent().getCurrentPolicy().getVulnerabilityScan().getEnabled()).thenReturn(false);
            nrMock.when(() -> NewRelicSecurity.getAgent().getCurrentPolicy().getVulnerabilityScan().getIastScan().getEnabled()).thenReturn(false);
            Assertions.assertTrue(JdbcHelper.skipExistsEvent());
            nrMock.clearInvocations();
            nrMock.reset();
        }
    }
    @Test
    public void skipExistsEventTest3() {
        try (MockedStatic<NewRelicSecurity> nrMock = Mockito.mockStatic(NewRelicSecurity.class, Answers.RETURNS_DEEP_STUBS)){
            nrMock.when(() -> NewRelicSecurity.getAgent().getCurrentPolicy().getVulnerabilityScan().getEnabled()).thenReturn(true);
            nrMock.when(() -> NewRelicSecurity.getAgent().getCurrentPolicy().getVulnerabilityScan().getIastScan().getEnabled()).thenReturn(true);
            Assertions.assertFalse(JdbcHelper.skipExistsEvent());
            nrMock.clearInvocations();
            nrMock.reset();
        }
    }

    @Test
    public void isLockAcquiredTest(){
        Assertions.assertFalse(JdbcHelper.isLockAcquired());
    }
    @Test
    public void isLockAcquiredTest1() {
        String customAttribute = NR_SEC_CUSTOM_ATTRIB_NAME + Thread.currentThread().getId();
        try (MockedStatic<NewRelicSecurity> nrMock = Mockito.mockStatic(NewRelicSecurity.class, Answers.RETURNS_DEEP_STUBS)){
            nrMock.when(() -> NewRelicSecurity.isHookProcessingActive()).thenReturn(true);
            nrMock.when(() -> NewRelicSecurity.getAgent().getSecurityMetaData().getCustomAttribute(customAttribute, Boolean.class)).thenReturn(true);
            Assertions.assertTrue(JdbcHelper.isLockAcquired());
            nrMock.clearInvocations();
            nrMock.reset();
        }
    }

    @Test
    public void acquireLockIfPossibleTest(){
        Assertions.assertFalse(JdbcHelper.acquireLockIfPossible());
    }
    @Test
    public void acquireLockIfPossibleTest1() {
        String customAttribute = NR_SEC_CUSTOM_ATTRIB_NAME + Thread.currentThread().getId();
        try (MockedStatic<NewRelicSecurity> nrMock = Mockito.mockStatic(NewRelicSecurity.class, Answers.RETURNS_DEEP_STUBS)){
            nrMock.when(() -> NewRelicSecurity.isHookProcessingActive()).thenReturn(true);
            SecurityMetaData metaData = new SecurityMetaData();
            metaData.addCustomAttribute(customAttribute, true);
            nrMock.when(() -> NewRelicSecurity.getAgent().getSecurityMetaData()).thenReturn(metaData);
            Assertions.assertFalse(JdbcHelper.acquireLockIfPossible());
            nrMock.clearInvocations();
            nrMock.reset();
        }
    }
    @Test
    public void acquireLockIfPossibleTest2() {
        try (MockedStatic<NewRelicSecurity> nrMock = Mockito.mockStatic(NewRelicSecurity.class, Answers.RETURNS_DEEP_STUBS)){
            nrMock.when(() -> NewRelicSecurity.isHookProcessingActive()).thenReturn(true);
            nrMock.when(() -> NewRelicSecurity.getAgent().getSecurityMetaData()).thenReturn(new SecurityMetaData());
            Assertions.assertTrue(JdbcHelper.acquireLockIfPossible());
            nrMock.clearInvocations();
            nrMock.reset();
        }
    }
    @Test
    public void getSQLTest() {
        try (MockedStatic<NewRelicSecurity> nrMock = Mockito.mockStatic(NewRelicSecurity.class, Answers.RETURNS_DEEP_STUBS)){
            nrMock.when(() -> NewRelicSecurity.isHookProcessingActive()).thenReturn(true);
            nrMock.when(() -> NewRelicSecurity.getAgent().getSecurityMetaData()).thenReturn(new SecurityMetaData());
            Assertions.assertTrue(JdbcHelper.acquireLockIfPossible());
            nrMock.clearInvocations();
            nrMock.reset();
        }
    }
    @Test
    public void detectDatabaseProductTest() {
        Assertions.assertEquals(JDBCVendor.MYSQL, JdbcHelper.detectDatabaseProduct(JdbcHelper.MY_SQL));
        Assertions.assertEquals(JDBCVendor.ORACLE, JdbcHelper.detectDatabaseProduct(JdbcHelper.ORACLE));
        Assertions.assertEquals(JDBCVendor.DERBY, JdbcHelper.detectDatabaseProduct(JdbcHelper.APACHE_DERBY));
        Assertions.assertEquals(JDBCVendor.HSQLDB, JdbcHelper.detectDatabaseProduct(JdbcHelper.HSQL_DATABASE_ENGINE));
        Assertions.assertEquals(JDBCVendor.SQLITE, JdbcHelper.detectDatabaseProduct(JdbcHelper.SQ_LITE));
        Assertions.assertEquals(JDBCVendor.H2, JdbcHelper.detectDatabaseProduct(JdbcHelper.H_2));
        Assertions.assertEquals(JDBCVendor.MSSQL, JdbcHelper.detectDatabaseProduct(JdbcHelper.MICROSOFT_SQL_SERVER));
        Assertions.assertEquals(JDBCVendor.ENTERPRISE_DB, JdbcHelper.detectDatabaseProduct(JdbcHelper.ENTERPRISE_DB));
        Assertions.assertEquals(JDBCVendor.PHOENIX, JdbcHelper.detectDatabaseProduct(JdbcHelper.PHOENIX));
        Assertions.assertEquals(JDBCVendor.POSTGRES, JdbcHelper.detectDatabaseProduct(JdbcHelper.POSTGRE_SQL));
        Assertions.assertEquals(JDBCVendor.IBMDB2, JdbcHelper.detectDatabaseProduct(JdbcHelper.DB_2));
        Assertions.assertEquals(JDBCVendor.VERTICA, JdbcHelper.detectDatabaseProduct(JdbcHelper.VERTICA));
        Assertions.assertEquals(JDBCVendor.SYBASE, JdbcHelper.detectDatabaseProduct(JdbcHelper.ASE));
        Assertions.assertEquals(JDBCVendor.SYBASE, JdbcHelper.detectDatabaseProduct(JdbcHelper.ADAPTIVE));
        Assertions.assertEquals(JDBCVendor.SYBASE, JdbcHelper.detectDatabaseProduct(JdbcHelper.SQL_SERVER));
        Assertions.assertEquals(JDBCVendor.SAPANA, JdbcHelper.detectDatabaseProduct(JdbcHelper.HDB));
        Assertions.assertEquals(JDBCVendor.GREENPLUM, JdbcHelper.detectDatabaseProduct(JdbcHelper.GREENPLUM));
        Assertions.assertEquals(JDBCVendor.SOLID_DB, JdbcHelper.detectDatabaseProduct(JdbcHelper.SOLID_DB));
        Assertions.assertEquals(JdbcHelper.UNKNOWN, JdbcHelper.detectDatabaseProduct("unknown"));
    }
}
