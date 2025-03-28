package com.newrelic.api.agent.security.instrumentation.helpers;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.schema.SecurityMetaData;
import com.newrelic.api.agent.security.schema.operation.FileIntegrityOperation;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Answers;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import java.io.File;
import java.io.IOException;
import java.util.UUID;

import static com.newrelic.api.agent.security.instrumentation.helpers.FileHelper.NR_SEC_CUSTOM_ATTRIB_NAME;

public class FileHelperTest {
    private final String CLASS_NAME = "className", METHOD_NAME = "methodName";
    private final File file = new File(String.format("/tmp/%s_file.java", UUID.randomUUID()));
    @Test
    public void getFileExtensionTest(){
        Assertions.assertEquals("", FileHelper.getFileExtension("file"));
        Assertions.assertEquals("txt", FileHelper.getFileExtension("file.txt"));
    }
    @Test
    public void createEntryOfFileIntegrityNullTest(){
        Assertions.assertNull(FileHelper.createEntryOfFileIntegrity("file", CLASS_NAME, METHOD_NAME));
        Assertions.assertNull(FileHelper.createEntryOfFileIntegrity("file.txt", CLASS_NAME, METHOD_NAME));
    }
    @Test
    public void createEntryOfFileIntegrityTest(){
        try (MockedStatic<NewRelicSecurity> nrMock = Mockito.mockStatic(NewRelicSecurity.class, Answers.RETURNS_DEEP_STUBS)){
            nrMock.when(() -> NewRelicSecurity.getAgent().getSecurityMetaData().getFileLocalMap().containsKey(file.getAbsolutePath())).thenReturn(false);
            assertion(file.exists(), file.getAbsolutePath(), FileHelper.createEntryOfFileIntegrity(file.getAbsolutePath(), CLASS_NAME, METHOD_NAME));
        }
    }
    @Test
    public void createEntryOfFileIntegrityTest1(){
        try (MockedStatic<NewRelicSecurity> nrMock = Mockito.mockStatic(NewRelicSecurity.class, Answers.RETURNS_DEEP_STUBS)){
            nrMock.when(() -> NewRelicSecurity.getAgent().getSecurityMetaData().getFileLocalMap().containsKey(file.getAbsolutePath())).thenReturn(true);
            Assertions.assertNull(FileHelper.createEntryOfFileIntegrity(file.getAbsolutePath(), CLASS_NAME, METHOD_NAME));
        }
    }
    @Test
    public void createEntryOfFileIntegrityTest2() throws IOException {
        try (MockedStatic<NewRelicSecurity> nrMock = Mockito.mockStatic(NewRelicSecurity.class, Answers.RETURNS_DEEP_STUBS)){
            file.createNewFile();
            nrMock.when(() -> NewRelicSecurity.getAgent().getSecurityMetaData().getFileLocalMap().containsKey(file.getAbsolutePath())).thenReturn(false);
            assertion(file.exists(), file.getAbsolutePath(), FileHelper.createEntryOfFileIntegrity(file.getAbsolutePath(), CLASS_NAME, METHOD_NAME));
            file.delete();
        }
    }
    @Test
    public void createEntryOfFileIntegrityTest3() throws IOException {
        try (MockedStatic<NewRelicSecurity> nrMock = Mockito.mockStatic(NewRelicSecurity.class, Answers.RETURNS_DEEP_STUBS)){
            file.createNewFile();
            nrMock.when(() -> NewRelicSecurity.getAgent().getSecurityMetaData().getFileLocalMap().containsKey(file.getAbsolutePath())).thenReturn(true);
            Assertions.assertNull(FileHelper.createEntryOfFileIntegrity(file.getAbsolutePath(), CLASS_NAME, METHOD_NAME));
            file.delete();
        }
    }

    @Test
    public void isFileLockAcquiredTest(){
        Assertions.assertFalse(FileHelper.isFileLockAcquired());
    }
    @Test
    public void isFileLockAcquiredTest1() {
        String customAttribute = NR_SEC_CUSTOM_ATTRIB_NAME + Thread.currentThread().getId();
        try (MockedStatic<NewRelicSecurity> nrMock = Mockito.mockStatic(NewRelicSecurity.class, Answers.RETURNS_DEEP_STUBS)){
            nrMock.when(() -> NewRelicSecurity.isHookProcessingActive()).thenReturn(true);
            nrMock.when(() -> NewRelicSecurity.getAgent().getSecurityMetaData().getCustomAttribute(customAttribute, Boolean.class)).thenReturn(true);
            Assertions.assertTrue(FileHelper.isFileLockAcquired());
            nrMock.clearInvocations();
            nrMock.reset();
        }
    }

    @Test
    public void acquireLockIfPossibleTest(){
        Assertions.assertFalse(FileHelper.acquireFileLockIfPossible());
    }
    @Test
    public void acquireLockIfPossibleTest1() {
        String customAttribute = NR_SEC_CUSTOM_ATTRIB_NAME + Thread.currentThread().getId();
        try (MockedStatic<NewRelicSecurity> nrMock = Mockito.mockStatic(NewRelicSecurity.class, Answers.RETURNS_DEEP_STUBS)){
            nrMock.when(() -> NewRelicSecurity.isHookProcessingActive()).thenReturn(true);
            SecurityMetaData metaData = new SecurityMetaData();
            metaData.addCustomAttribute(customAttribute, true);
            nrMock.when(() -> NewRelicSecurity.getAgent().getSecurityMetaData()).thenReturn(metaData);
            Assertions.assertFalse(FileHelper.acquireFileLockIfPossible());
            nrMock.clearInvocations();
            nrMock.reset();
        }
    }
    @Test
    public void acquireLockIfPossibleTest2() {
        try (MockedStatic<NewRelicSecurity> nrMock = Mockito.mockStatic(NewRelicSecurity.class, Answers.RETURNS_DEEP_STUBS)){
            nrMock.when(() -> NewRelicSecurity.isHookProcessingActive()).thenReturn(true);
            nrMock.when(() -> NewRelicSecurity.getAgent().getSecurityMetaData()).thenReturn(new SecurityMetaData());
            Assertions.assertTrue(FileHelper.acquireFileLockIfPossible());
            nrMock.clearInvocations();
            nrMock.reset();
        }
    }

    private void assertion(boolean exists, String fileName, FileIntegrityOperation op){
        Assertions.assertNotNull(op);
        Assertions.assertEquals(exists, op.getExists());
        Assertions.assertEquals(fileName, op.getFileName());
        Assertions.assertEquals(CLASS_NAME, op.getClassName());
        Assertions.assertEquals(METHOD_NAME, op.getMethodName());
    }

}
