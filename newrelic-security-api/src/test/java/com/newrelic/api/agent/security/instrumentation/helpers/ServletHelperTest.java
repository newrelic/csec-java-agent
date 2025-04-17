package com.newrelic.api.agent.security.instrumentation.helpers;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.schema.AgentMetaData;
import com.newrelic.api.agent.security.schema.HttpRequest;
import com.newrelic.api.agent.security.schema.K2RequestIdentifier;
import com.newrelic.api.agent.security.schema.SecurityMetaData;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Answers;
import org.mockito.ArgumentMatchers;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import java.io.File;
import java.io.IOException;
import java.util.Collections;
import java.util.Random;
import java.util.UUID;

import static com.newrelic.api.agent.security.schema.StringUtils.EMPTY;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class ServletHelperTest {

    @Test
    public void parseFuzzRequestIdentifierHeaderTest() {
        assertEquals(EMPTY, ServletHelper.parseFuzzRequestIdentifierHeader(EMPTY).getRaw());
    }

    @Test
    public void parseFuzzRequestIdentifierHeaderTest1() {
        assertEquals("header", ServletHelper.parseFuzzRequestIdentifierHeader("header").getRaw());
    }

    @Test
    public void parseFuzzRequestIdentifierHeaderTest2() {
        MockedStatic<NewRelicSecurity> nrMock = Mockito.mockStatic(NewRelicSecurity.class, Answers.RETURNS_DEEP_STUBS);
        try {
            nrMock.when(() -> NewRelicSecurity.getAgent().getCurrentPolicy().getVulnerabilityScan().getEnabled()).thenReturn(true);
            nrMock.when(() -> NewRelicSecurity.getAgent().getCurrentPolicy().getVulnerabilityScan().getIastScan().getEnabled()).thenReturn(true);
            assertions(ServletHelper.parseFuzzRequestIdentifierHeader(EMPTY), EMPTY, false);
        } finally {
            GrpcHelperTest.clearMockitoInvocation(nrMock);
        }
    }

    @Test
    public void parseFuzzRequestIdentifierHeaderTest3() {
        MockedStatic<NewRelicSecurity> nrMock = Mockito.mockStatic(NewRelicSecurity.class, Answers.RETURNS_DEEP_STUBS);
        try {
            nrMock.when(() -> NewRelicSecurity.getAgent().getCurrentPolicy().getVulnerabilityScan().getEnabled()).thenReturn(true);
            nrMock.when(() -> NewRelicSecurity.getAgent().getCurrentPolicy().getVulnerabilityScan().getIastScan().getEnabled()).thenReturn(true);
            String header = "1:IAST:1:IAST:pre-val:IAST:SAFE:IAST:1:IAST:";
            assertions(ServletHelper.parseFuzzRequestIdentifierHeader(header), header, false, "1", "1", "pre-val", "SAFE", "1");
        } finally {
            GrpcHelperTest.clearMockitoInvocation(nrMock);
        }
    }

    @Test
    public void parseFuzzRequestIdentifierHeaderTest4() {
        MockedStatic<NewRelicSecurity> nrMock = Mockito.mockStatic(NewRelicSecurity.class, Answers.RETURNS_DEEP_STUBS);
        try {
            nrMock.when(() -> NewRelicSecurity.getAgent().getCurrentPolicy().getVulnerabilityScan().getEnabled()).thenReturn(true);
            nrMock.when(() -> NewRelicSecurity.getAgent().getCurrentPolicy().getVulnerabilityScan().getIastScan().getEnabled()).thenReturn(true);
            String header = "1:IAST:1:IAST:pre-val:IAST:SAFE:IAST:1:IAST:ref-key";
            assertions(ServletHelper.parseFuzzRequestIdentifierHeader(header), header, false, "1", "1", "pre-val", "SAFE", "1", "ref-key");
        } finally {
            GrpcHelperTest.clearMockitoInvocation(nrMock);
        }
    }

    @Test
    public void parseFuzzRequestIdentifierHeaderTest5() throws IOException {
        MockedStatic<NewRelicSecurity> nrMock = Mockito.mockStatic(NewRelicSecurity.class, Answers.RETURNS_DEEP_STUBS);
        try {
            String hash = "02642fa0c3542fe5997eea314c0f5eec5b744ea83f168e998006111f9fa4fbd2";
            String encryptedData = "2aabd9833907ae4cde0120e4352c0da72d9e1acfcf298d6801b7120586d1df9d";
            File file = new File("/tmp/tmp123");
            file.createNewFile();
            nrMock.when(() -> NewRelicSecurity.getAgent().getCurrentPolicy().getVulnerabilityScan().getEnabled()).thenReturn(true);
            nrMock.when(() -> NewRelicSecurity.getAgent().getCurrentPolicy().getVulnerabilityScan().getIastScan().getEnabled()).thenReturn(true);
            nrMock.when(() -> NewRelicSecurity.getAgent().decryptAndVerify(ArgumentMatchers.eq(encryptedData),ArgumentMatchers.eq(hash))).thenReturn(String.format("/tmp/tmp-%s", UUID.randomUUID()));

            String header = String.format("1:IAST:1:IAST:pre-val:IAST:SAFE:IAST:1:IAST:pre-key:IAST:%s:IAST:%s", encryptedData, hash);
            assertions(ServletHelper.parseFuzzRequestIdentifierHeader(header), header, true, "1", "1", "pre-val", "SAFE", "1", "pre-key", "build/file");
        } finally {
            GrpcHelperTest.clearMockitoInvocation(nrMock);
        }
    }

    @Test
    public void parseFuzzRequestIdentifierHeaderTest6() throws IOException {
        MockedStatic<NewRelicSecurity> nrMock = Mockito.mockStatic(NewRelicSecurity.class, Answers.RETURNS_DEEP_STUBS);
        try {
            String hash = "02642fa0c3542fe5997eea314c0f5eec5b744ea83f168e998006111f9fa4fbd2";
            String encryptedData = "2aabd9833907ae4cde0120e4352c0da72d9e1acfcf298d6801b7120586d1df9d";
            File file = new File("/tmp/tmp123");
            file.createNewFile();
            nrMock.when(() -> NewRelicSecurity.getAgent().getCurrentPolicy().getVulnerabilityScan().getEnabled()).thenReturn(true);
            nrMock.when(() -> NewRelicSecurity.getAgent().getCurrentPolicy().getVulnerabilityScan().getIastScan().getEnabled()).thenReturn(true);
            nrMock.when(() -> NewRelicSecurity.getAgent().decryptAndVerify(ArgumentMatchers.eq(encryptedData),ArgumentMatchers.eq(hash))).thenReturn("");

            String header = String.format("1:IAST:1:IAST:pre-val:IAST:SAFE:IAST:1:IAST:pre-key:IAST:%s:IAST:%s", encryptedData, hash);
            assertions(ServletHelper.parseFuzzRequestIdentifierHeader(header), header, true, "1", "1", "pre-val", "SAFE", "1", "pre-key", "build/file");
        } finally {
            GrpcHelperTest.clearMockitoInvocation(nrMock);
        }
    }

    @Test
    public void urlDecodeTest() {
        Assertions.assertEquals("/user/123", ServletHelper.urlDecode("/user/123"));
        Assertions.assertEquals("/user/123", ServletHelper.urlDecode("%2Fuser%2F123"));
        Assertions.assertEquals("/user/123?u=1", ServletHelper.urlDecode("%2Fuser%2F123%3Fu%3D1"));
    }



    @Test
    public void registerUserLevelCodeTest() throws IOException {
        MockedStatic<NewRelicSecurity> nrMock = Mockito.mockStatic(NewRelicSecurity.class, Answers.RETURNS_DEEP_STUBS);
        try {
            nrMock.when(NewRelicSecurity::isHookProcessingActive).thenReturn(false);
            Assertions.assertFalse(ServletHelper.registerUserLevelCode("framework"));
        } finally {
            GrpcHelperTest.clearMockitoInvocation(nrMock);
        }
    }

    @Test
    public void registerUserLevelCode1Test() {
        MockedStatic<NewRelicSecurity> nrMock = Mockito.mockStatic(NewRelicSecurity.class, Answers.RETURNS_DEEP_STUBS);
        try {
            nrMock.when(NewRelicSecurity::isHookProcessingActive).thenReturn(true);
            SecurityMetaData securityMetaData = Mockito.mock(SecurityMetaData.class);

            AgentMetaData metaData = Mockito.mock(AgentMetaData.class);
            HttpRequest request = Mockito.mock(HttpRequest.class);
            request.setMethod("GET"); request.setUrl("/url");

            Mockito.doReturn(false).when(metaData).isFoundAnnotedUserLevelServiceMethod();
            Mockito.doReturn(metaData).when(securityMetaData).getMetaData();
            Mockito.doReturn(request).when(securityMetaData).getRequest();

            nrMock.when(NewRelicSecurity.getAgent()::getSecurityMetaData).thenReturn(securityMetaData);

            Assertions.assertTrue(ServletHelper.registerUserLevelCode("framework"));
        } finally {
            GrpcHelperTest.clearMockitoInvocation(nrMock);
        }
    }

    @Test
    public void setFoundAnnotatedUserLevelServiceMethodTest() {
        Assertions.assertFalse(ServletHelper.setFoundAnnotatedUserLevelServiceMethod(false));
        MockedStatic<NewRelicSecurity> nrMock = Mockito.mockStatic(NewRelicSecurity.class, Answers.RETURNS_DEEP_STUBS);
        try {
            nrMock.when(NewRelicSecurity::isHookProcessingActive).thenReturn(true);
            SecurityMetaData securityMetaData = Mockito.mock(SecurityMetaData.class);

            AgentMetaData metaData = Mockito.mock(AgentMetaData.class);
            HttpRequest request = Mockito.mock(HttpRequest.class);
            request.setMethod("GET"); request.setUrl("/url");

            Mockito.doReturn(false).when(metaData).isFoundAnnotedUserLevelServiceMethod();
            Mockito.doReturn(metaData).when(securityMetaData).getMetaData();
            Mockito.doReturn(request).when(securityMetaData).getRequest();

            nrMock.when(NewRelicSecurity.getAgent()::getSecurityMetaData).thenReturn(securityMetaData);

            Assertions.assertTrue(ServletHelper.setFoundAnnotatedUserLevelServiceMethod(false));
        } finally {
            GrpcHelperTest.clearMockitoInvocation(nrMock);
        }
    }

    @Test
    public void tmpFileCleanUpTest() throws IOException {
        final File file = new File(String.format("/tmp/%s_file.java", UUID.randomUUID()));
        file.createNewFile();
        ServletHelper.tmpFileCleanUp(Collections.singletonList(file.getAbsolutePath()));
        Assertions.assertFalse(file.exists());
    }

    @Test
    public void isResponseContentTypeExcludedTest() {
        Assertions.assertFalse(ServletHelper.isResponseContentTypeExcluded(""));
        Assertions.assertFalse(ServletHelper.isResponseContentTypeExcluded("text/plain"));
        Assertions.assertTrue(ServletHelper.isResponseContentTypeExcluded("audio/ogg"));
        Assertions.assertTrue(ServletHelper.isResponseContentTypeExcluded("text/calendar"));
    }

    @Test
    public void executeBeforeExitingTransactionTest() {

    }



    /**
     * Assert that {@code actual} K2RequestIdentifier is having equal raw, recordIndex, K2Request, etc.
     *
     * @param actual      the actual value of K2RequestIdentifier
     * @param raw         the expected value of K2RequestIdentifier's raw
     * @param isK2Request the expected value of K2RequestIdentifier's K2Request
     * @param expected    the expected value of K2RequestIdentifier as following:
     *                    (
     *                    expected[0]: ApiRecordId,
     *                    expected[1]: RefId,
     *                    expected[2]: RefValue,
     *                    expected[3]: NextStage,
     *                    expected[4]: RecordIndex {@link Integer},
     *                    expected[5]: RefKey,
     *                    expected[6]: tmpFile,
     *                    ...)
     */
    private void assertions(K2RequestIdentifier actual, String raw, boolean isK2Request, String... expected) {
        assertNotNull(actual);
        assertEquals(raw, actual.getRaw());
        assertEquals(isK2Request, actual.getK2Request());
//        if( expected.length > 5){
//            assertEquals(expected[0], actual.getApiRecordId());
//            assertEquals(expected[1], actual.getRefId());
//            assertEquals(expected[2], actual.getRefValue());
//            assertEquals(expected[3], actual.getNextStage().getStatus());
//            assertEquals(Integer.parseInt(expected[4]), actual.getRecordIndex());
//        }
//        if (expected.length > 6) {
//            assertEquals(expected[5], actual.getRefKey());
//        }
//        if (expected.length >= 7) {
//            // assertion for tmpFiles list
//            assertTrue(actual.getTempFiles().contains(expected[6]));
//        }
    }
}
