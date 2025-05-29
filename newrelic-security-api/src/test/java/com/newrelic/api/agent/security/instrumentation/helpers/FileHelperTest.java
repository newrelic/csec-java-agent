package com.newrelic.api.agent.security.instrumentation.helpers;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.schema.operation.FileIntegrityOperation;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Answers;
import org.mockito.ArgumentMatchers;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.verification.VerificationMode;

import java.io.File;
import java.io.IOException;
import java.util.Collections;
import java.util.UUID;

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
        MockedStatic<NewRelicSecurity> nrMock = Mockito.mockStatic(NewRelicSecurity.class, Answers.RETURNS_DEEP_STUBS);
        try {
            nrMock.when(() -> NewRelicSecurity.getAgent().getSecurityMetaData().getFileLocalMap().containsKey(file.getAbsolutePath())).thenReturn(false);
            assertion(file.exists(), file.getAbsolutePath(), FileHelper.createEntryOfFileIntegrity(file.getAbsolutePath(), CLASS_NAME, METHOD_NAME));
        } finally {
            GrpcHelperTest.clearMockitoInvocation(nrMock);
        }
    }
    @Test
    public void createEntryOfFileIntegrityTest1(){
        MockedStatic<NewRelicSecurity> nrMock = Mockito.mockStatic(NewRelicSecurity.class, Answers.RETURNS_DEEP_STUBS);
        try {
            nrMock.when(() -> NewRelicSecurity.getAgent().getSecurityMetaData().getFileLocalMap().containsKey(file.getAbsolutePath())).thenReturn(true);
            Assertions.assertNull(FileHelper.createEntryOfFileIntegrity(file.getAbsolutePath(), CLASS_NAME, METHOD_NAME));
        } finally {
            GrpcHelperTest.clearMockitoInvocation(nrMock);
        }
    }
    @Test
    public void createEntryOfFileIntegrityTest2() throws IOException {
        MockedStatic<NewRelicSecurity> nrMock = Mockito.mockStatic(NewRelicSecurity.class, Answers.RETURNS_DEEP_STUBS);
        try {
            file.createNewFile();
            nrMock.when(() -> NewRelicSecurity.getAgent().getSecurityMetaData().getFileLocalMap().containsKey(file.getAbsolutePath())).thenReturn(false);
            assertion(file.exists(), file.getAbsolutePath(), FileHelper.createEntryOfFileIntegrity(file.getAbsolutePath(), CLASS_NAME, METHOD_NAME));
            file.delete();
        } finally {
            GrpcHelperTest.clearMockitoInvocation(nrMock);
        }
    }

    @Test
    public void createEntryOfFileIntegrityTest3() throws IOException {
        MockedStatic<NewRelicSecurity> nrMock = Mockito.mockStatic(NewRelicSecurity.class, Answers.RETURNS_DEEP_STUBS);
        try {
            file.createNewFile();
            nrMock.when(() -> NewRelicSecurity.getAgent().getSecurityMetaData().getFileLocalMap().containsKey(file.getAbsolutePath())).thenReturn(true);
            Assertions.assertNull(FileHelper.createEntryOfFileIntegrity(file.getAbsolutePath(), CLASS_NAME, METHOD_NAME));
            file.delete();
        } finally {
            GrpcHelperTest.clearMockitoInvocation(nrMock);
        }
    }

    @Test
    public void skipExistsEventTest() {
        MockedStatic<NewRelicSecurity> nrMock = Mockito.mockStatic(NewRelicSecurity.class, Answers.RETURNS_DEEP_STUBS);
        try {
            nrMock.when(() -> NewRelicSecurity.getAgent().getSecurityMetaData().getFileLocalMap().containsKey(file.getAbsolutePath())).thenReturn(true);
            nrMock.when(NewRelicSecurity.getAgent().getCurrentPolicy().getVulnerabilityScan()::getEnabled).thenReturn(true);
            nrMock.when(NewRelicSecurity.getAgent().getCurrentPolicy().getVulnerabilityScan().getIastScan()::getEnabled).thenReturn(true);

            Assertions.assertFalse(FileHelper.skipExistsEvent(file.getAbsolutePath()));

        } finally {
            GrpcHelperTest.clearMockitoInvocation(nrMock);
        }
    }

    @Test
    public void skipExistsEvent1Test() {
        MockedStatic<NewRelicSecurity> nrMock = Mockito.mockStatic(NewRelicSecurity.class, Answers.RETURNS_DEEP_STUBS);
        try {
            nrMock.when(NewRelicSecurity.getAgent().getCurrentPolicy().getVulnerabilityScan()::getEnabled).thenReturn(false);
            nrMock.when(NewRelicSecurity.getAgent().getCurrentPolicy().getVulnerabilityScan().getIastScan()::getEnabled).thenReturn(false);

            Assertions.assertTrue(FileHelper.skipExistsEvent(file.getAbsolutePath()));

        } finally {
            GrpcHelperTest.clearMockitoInvocation(nrMock);
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
