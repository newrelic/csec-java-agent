package com.newrelic.api.agent.security.instrumentation.helpers;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.schema.K2RequestIdentifier;
import org.junit.jupiter.api.Test;
import org.mockito.Answers;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import static com.newrelic.api.agent.security.schema.StringUtils.EMPTY;
import static org.junit.jupiter.api.Assertions.assertEquals;
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
        try (MockedStatic<NewRelicSecurity> nrMock = Mockito.mockStatic(NewRelicSecurity.class, Answers.RETURNS_DEEP_STUBS)) {
            nrMock.when(() -> NewRelicSecurity.getAgent().getCurrentPolicy().getVulnerabilityScan().getEnabled()).thenReturn(true);
            nrMock.when(() -> NewRelicSecurity.getAgent().getCurrentPolicy().getVulnerabilityScan().getIastScan().getEnabled()).thenReturn(true);
            assertions(ServletHelper.parseFuzzRequestIdentifierHeader(EMPTY), EMPTY, false);
        }
    }
    @Test
    public void parseFuzzRequestIdentifierHeaderTest3() {
        try (MockedStatic<NewRelicSecurity> nrMock = Mockito.mockStatic(NewRelicSecurity.class, Answers.RETURNS_DEEP_STUBS)) {
            nrMock.when(() -> NewRelicSecurity.getAgent().getCurrentPolicy().getVulnerabilityScan().getEnabled()).thenReturn(true);
            nrMock.when(() -> NewRelicSecurity.getAgent().getCurrentPolicy().getVulnerabilityScan().getIastScan().getEnabled()).thenReturn(true);
            String header = "1:IAST:1:IAST:pre-val:IAST:SAFE:IAST:1:IAST:";
            assertions(ServletHelper.parseFuzzRequestIdentifierHeader(header), header, true, "1", "1", "pre-val", "SAFE", "1");
        }
    }
    @Test
    public void parseFuzzRequestIdentifierHeaderTest4() {
        try (MockedStatic<NewRelicSecurity> nrMock = Mockito.mockStatic(NewRelicSecurity.class, Answers.RETURNS_DEEP_STUBS)) {
            nrMock.when(() -> NewRelicSecurity.getAgent().getCurrentPolicy().getVulnerabilityScan().getEnabled()).thenReturn(true);
            nrMock.when(() -> NewRelicSecurity.getAgent().getCurrentPolicy().getVulnerabilityScan().getIastScan().getEnabled()).thenReturn(true);
            String header = "1:IAST:1:IAST:pre-val:IAST:SAFE:IAST:1:IAST:pre-key";
            assertions(ServletHelper.parseFuzzRequestIdentifierHeader(header), header, true, "1", "1", "pre-val", "SAFE", "1", "pre-key");
        }
    }
    @Test
    public void parseFuzzRequestIdentifierHeaderTest5() {
        try (MockedStatic<NewRelicSecurity> nrMock = Mockito.mockStatic(NewRelicSecurity.class, Answers.RETURNS_DEEP_STUBS)) {
            nrMock.when(() -> NewRelicSecurity.getAgent().getCurrentPolicy().getVulnerabilityScan().getEnabled()).thenReturn(true);
            nrMock.when(() -> NewRelicSecurity.getAgent().getCurrentPolicy().getVulnerabilityScan().getIastScan().getEnabled()).thenReturn(true);
            String header = "1:IAST:1:IAST:pre-val:IAST:SAFE:IAST:1:IAST:pre-key:IAST:build/file";
            assertions(ServletHelper.parseFuzzRequestIdentifierHeader(header), header, true, "1", "1", "pre-val", "SAFE", "1", "pre-key", "build/file");
        }
    }

    /**
     * Assert that {@code actual} K2RequestIdentifier is having equal raw, recordIndex, K2Request, etc.
     * @param actual the actual value of K2RequestIdentifier
     * @param raw the expected value of K2RequestIdentifier's raw
     * @param isK2Request the expected value of K2RequestIdentifier's K2Request
     * @param expected the expected value of K2RequestIdentifier as following:
     * (
     * expected[0]: ApiRecordId,
     * expected[1]: RefId,
     * expected[2]: RefValue,
     * expected[3]: NextStage,
     * expected[4]: RecordIndex {@link Integer},
     * expected[5]: RefKey,
     * expected[6]: tmpFile,
     * ...)
     */
    private void assertions(K2RequestIdentifier actual, String raw, boolean isK2Request, String... expected) {
        assertNotNull(actual);
        assertEquals(raw, actual.getRaw());
        assertEquals(isK2Request, actual.getK2Request());
        if( expected.length > 5){
            assertEquals(expected[0], actual.getApiRecordId());
            assertEquals(expected[1], actual.getRefId());
            assertEquals(expected[2], actual.getRefValue());
            assertEquals(expected[3], actual.getNextStage().getStatus());
            assertEquals(Integer.parseInt(expected[4]), actual.getRecordIndex());
        }
        if(expected.length > 6){
            assertEquals(expected[5], actual.getRefKey());
        }
        if( expected.length >= 7){
            // assertion for tmpFiles list
            assertTrue(actual.getTempFiles().contains(expected[6]));
        }
    }
}
