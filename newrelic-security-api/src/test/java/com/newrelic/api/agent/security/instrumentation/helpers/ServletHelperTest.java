package com.newrelic.api.agent.security.instrumentation.helpers;

import com.newrelic.api.agent.security.NewRelicSecurity;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Answers;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import static com.newrelic.api.agent.security.schema.StringUtils.EMPTY;

public class ServletHelperTest {

    @Test
    public void parseFuzzRequestIdentifierHeader() {
        Assertions.assertEquals(EMPTY, ServletHelper.parseFuzzRequestIdentifierHeader(EMPTY).getRaw());
    }
    @Test
    public void parseFuzzRequestIdentifierHeader1() {
        Assertions.assertEquals("header", ServletHelper.parseFuzzRequestIdentifierHeader("header").getRaw());
    }
    @Test
    public void parseFuzzRequestIdentifierHeader2() {
        try (MockedStatic<NewRelicSecurity> nrMock = Mockito.mockStatic(NewRelicSecurity.class, Answers.RETURNS_DEEP_STUBS)) {
            nrMock.when(() -> NewRelicSecurity.getAgent().getCurrentPolicy().getVulnerabilityScan().getEnabled()).thenReturn(true);
            nrMock.when(() -> NewRelicSecurity.getAgent().getCurrentPolicy().getVulnerabilityScan().getIastScan().getEnabled()).thenReturn(true);
            Assertions.assertEquals(EMPTY, ServletHelper.parseFuzzRequestIdentifierHeader(EMPTY).getRaw());
        }
    }
    @Test
    public void parseFuzzRequestIdentifierHeader3() {
        try (MockedStatic<NewRelicSecurity> nrMock = Mockito.mockStatic(NewRelicSecurity.class, Answers.RETURNS_DEEP_STUBS)) {
            nrMock.when(() -> NewRelicSecurity.getAgent().getCurrentPolicy().getVulnerabilityScan().getEnabled()).thenReturn(true);
            nrMock.when(() -> NewRelicSecurity.getAgent().getCurrentPolicy().getVulnerabilityScan().getIastScan().getEnabled()).thenReturn(true);
            String header = "1:IAST:1:IAST:pre-val:IAST:SAFE:IAST:1:IAST: ";
            Assertions.assertEquals(header, ServletHelper.parseFuzzRequestIdentifierHeader(header).getRaw());
        }
    }
    @Test
    public void parseFuzzRequestIdentifierHeader4() {
        try (MockedStatic<NewRelicSecurity> nrMock = Mockito.mockStatic(NewRelicSecurity.class, Answers.RETURNS_DEEP_STUBS)) {
            nrMock.when(() -> NewRelicSecurity.getAgent().getCurrentPolicy().getVulnerabilityScan().getEnabled()).thenReturn(true);
            nrMock.when(() -> NewRelicSecurity.getAgent().getCurrentPolicy().getVulnerabilityScan().getIastScan().getEnabled()).thenReturn(true);
            String header = "1:IAST:1:IAST:pre-val:IAST:SAFE:IAST:1:IAST:pre-key";
            Assertions.assertEquals(header, ServletHelper.parseFuzzRequestIdentifierHeader(header).getRaw());
        }

    }

}
