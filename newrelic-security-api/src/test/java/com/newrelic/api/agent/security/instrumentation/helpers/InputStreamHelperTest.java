package com.newrelic.api.agent.security.instrumentation.helpers;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.schema.SecurityMetaData;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Answers;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import java.util.Collections;
import java.util.HashSet;

public class InputStreamHelperTest {
    @Test
    public void processRequestInputStreamHookDataTest(){
        Assertions.assertFalse(InputStreamHelper.processRequestInputStreamHookData(null));
    }
    @Test
    public void processRequestInputStreamHookDataTest1(){
        try (MockedStatic<NewRelicSecurity> nrMock = Mockito.mockStatic(NewRelicSecurity.class, Answers.RETURNS_DEEP_STUBS)) {
            nrMock.when(() -> NewRelicSecurity.isHookProcessingActive()).thenReturn(true);
            Assertions.assertFalse(InputStreamHelper.processRequestInputStreamHookData(null));
        }
    }
    @Test
    public void processRequestInputStreamHookDataTest2(){
        try (MockedStatic<NewRelicSecurity> nrMock = Mockito.mockStatic(NewRelicSecurity.class, Answers.RETURNS_DEEP_STUBS)) {
            nrMock.when(() -> NewRelicSecurity.isHookProcessingActive()).thenReturn(true);
            nrMock.when(() -> NewRelicSecurity.getAgent().getSecurityMetaData()).thenReturn(new SecurityMetaData());
            Assertions.assertFalse(InputStreamHelper.processRequestInputStreamHookData(null));
        }
    }
    @Test
    public void processRequestInputStreamHookDataTest3(){
        try (MockedStatic<NewRelicSecurity> nrMock = Mockito.mockStatic(NewRelicSecurity.class, Answers.RETURNS_DEEP_STUBS)) {
            nrMock.when(() -> NewRelicSecurity.isHookProcessingActive()).thenReturn(true);
            SecurityMetaData metaData = new SecurityMetaData();
            metaData.addCustomAttribute("REQUEST_INPUTSTREAM_HASH", new HashSet<>());
            nrMock.when(() -> NewRelicSecurity.getAgent().getSecurityMetaData()).thenReturn(metaData);
            Assertions.assertFalse(InputStreamHelper.processRequestInputStreamHookData(0));
        }
    }
    @Test
    public void processRequestInputStreamHookDataTest4(){
        try (MockedStatic<NewRelicSecurity> nrMock = Mockito.mockStatic(NewRelicSecurity.class, Answers.RETURNS_DEEP_STUBS)) {
            nrMock.when(() -> NewRelicSecurity.isHookProcessingActive()).thenReturn(true);
            SecurityMetaData metaData = new SecurityMetaData();
            metaData.addCustomAttribute("REQUEST_INPUTSTREAM_HASH", new HashSet<>(Collections.singletonList(hashCode())));
            nrMock.when(() -> NewRelicSecurity.getAgent().getSecurityMetaData()).thenReturn(metaData);
            Assertions.assertTrue(InputStreamHelper.processRequestInputStreamHookData(hashCode()));
        }
    }
}
