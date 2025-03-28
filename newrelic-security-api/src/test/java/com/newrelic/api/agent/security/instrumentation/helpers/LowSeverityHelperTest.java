package com.newrelic.api.agent.security.instrumentation.helpers;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.schema.HttpRequest;
import com.newrelic.api.agent.security.schema.K2RequestIdentifier;
import com.newrelic.api.agent.security.schema.SecurityMetaData;
import com.newrelic.api.agent.security.schema.StringUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Answers;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

public class LowSeverityHelperTest {
    @Test
    public void addLowSeverityEventToEncounteredListTest(){
        Assertions.assertTrue(LowSeverityHelper.addLowSeverityEventToEncounteredList(hashCode()));
        Assertions.assertFalse(LowSeverityHelper.addLowSeverityEventToEncounteredList(hashCode()));
    }
    @Test
    public void checkIfLowSeverityEventAlreadyEncounteredTest(){
        Assertions.assertFalse(LowSeverityHelper.checkIfLowSeverityEventAlreadyEncountered(hashCode()));
    }
    @Test
    public void checkIfLowSeverityEventAlreadyEncounteredTest1(){
        LowSeverityHelper.addLowSeverityEventToEncounteredList(hashCode());
        LowSeverityHelper.clearLowSeverityEventFilter();
        Assertions.assertFalse(LowSeverityHelper.checkIfLowSeverityEventAlreadyEncountered(hashCode()));
    }
    @Test
    public void checkIfLowSeverityEventAlreadyEncounteredTest2(){
        LowSeverityHelper.addLowSeverityEventToEncounteredList(hashCode());
        Assertions.assertTrue(LowSeverityHelper.checkIfLowSeverityEventAlreadyEncountered(hashCode()));
    }
    @Test
    public void addRequestUriToEventFilterFalseTest(){
        Assertions.assertFalse(LowSeverityHelper.addRrequestUriToEventFilter(null));
        Assertions.assertFalse(LowSeverityHelper.addRrequestUriToEventFilter(Mockito.mock(HttpRequest.class)));
    }
    @Test
    public void addRequestUriToEventFilterTrueTest(){
        HttpRequest req = new HttpRequest();
        req.setUrl("url");
        Assertions.assertTrue(LowSeverityHelper.addRrequestUriToEventFilter(req));
        Assertions.assertFalse(LowSeverityHelper.addRrequestUriToEventFilter(req));
    }
    @Test
    public void isOwaspHookProcessingNeededTest(){
        Assertions.assertFalse(LowSeverityHelper.isOwaspHookProcessingNeeded());
    }
    @Test
    public void isOwaspHookProcessingNeededTest1(){
        try (MockedStatic<NewRelicSecurity> nrMock = Mockito.mockStatic(NewRelicSecurity.class, Answers.RETURNS_DEEP_STUBS)) {
            nrMock.when(() -> NewRelicSecurity.getAgent().getSecurityMetaData()).thenReturn(new SecurityMetaData());
            Assertions.assertFalse(LowSeverityHelper.isOwaspHookProcessingNeeded());
            nrMock.clearInvocations();
            nrMock.reset();
        }
    }
    @Test
    public void isOwaspHookProcessingNeededTest2(){
        try (MockedStatic<NewRelicSecurity> nrMock = Mockito.mockStatic(NewRelicSecurity.class, Answers.RETURNS_DEEP_STUBS)) {
            SecurityMetaData metaData = new SecurityMetaData();

            HttpRequest request = new HttpRequest(); request.setUrl(StringUtils.EMPTY);
            metaData.setRequest(request);

            metaData.setFuzzRequestIdentifier(new K2RequestIdentifier());
            nrMock.when(() -> NewRelicSecurity.getAgent().getSecurityMetaData()).thenReturn(metaData);
            Assertions.assertFalse(LowSeverityHelper.isOwaspHookProcessingNeeded());

            nrMock.clearInvocations();
            nrMock.reset();
        }
    }
    @Test
    public void isOwaspHookProcessingNeededTest3(){
        try (MockedStatic<NewRelicSecurity> nrMock = Mockito.mockStatic(NewRelicSecurity.class, Answers.RETURNS_DEEP_STUBS)) {
            SecurityMetaData metaData = new SecurityMetaData();

            HttpRequest request = new HttpRequest(); request.setUrl(StringUtils.EMPTY);
            metaData.setRequest(request);

            K2RequestIdentifier identifier = new K2RequestIdentifier(); identifier.setK2Request(true);
            metaData.setFuzzRequestIdentifier(identifier);
            nrMock.when(() -> NewRelicSecurity.getAgent().getSecurityMetaData()).thenReturn(metaData);

            Assertions.assertTrue(LowSeverityHelper.isOwaspHookProcessingNeeded());

            nrMock.clearInvocations();
            nrMock.reset();
        }
    }
    @Test
    public void isOwaspHookProcessingNeededTest4(){
        try (MockedStatic<NewRelicSecurity> nrMock = Mockito.mockStatic(NewRelicSecurity.class, Answers.RETURNS_DEEP_STUBS)) {
            SecurityMetaData metaData = new SecurityMetaData();

            HttpRequest request = new HttpRequest(); request.setUrl("url");
            metaData.setRequest(request);

            K2RequestIdentifier identifier = new K2RequestIdentifier(); identifier.setK2Request(true);
            metaData.setFuzzRequestIdentifier(identifier);
            nrMock.when(() -> NewRelicSecurity.getAgent().getSecurityMetaData()).thenReturn(metaData);
            Assertions.assertTrue(LowSeverityHelper.isOwaspHookProcessingNeeded());

            nrMock.clearInvocations();
            nrMock.reset();
        }
    }
}
