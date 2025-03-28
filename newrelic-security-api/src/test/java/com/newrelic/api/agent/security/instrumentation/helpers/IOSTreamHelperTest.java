package com.newrelic.api.agent.security.instrumentation.helpers;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.schema.SecurityMetaData;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Answers;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import java.util.HashSet;

public class IOSTreamHelperTest {
    @Test
    public void processRequestReaderHookDataTest(){
        Assertions.assertFalse(IOStreamHelper.processRequestReaderHookData(null));
    }
    @Test
    public void processRequestReaderHookDataTest1(){
        try (MockedStatic<NewRelicSecurity> nrMock = Mockito.mockStatic(NewRelicSecurity.class, Answers.RETURNS_DEEP_STUBS)) {
            nrMock.when(() -> NewRelicSecurity.isHookProcessingActive()).thenReturn(true);
            Assertions.assertFalse(IOStreamHelper.processRequestReaderHookData(null));
            nrMock.clearInvocations();
            nrMock.reset();
        }
    }
    @Test
    public void processRequestReaderHookDataTest2(){
        try (MockedStatic<NewRelicSecurity> nrMock = Mockito.mockStatic(NewRelicSecurity.class, Answers.RETURNS_DEEP_STUBS)) {
            nrMock.when(() -> NewRelicSecurity.isHookProcessingActive()).thenReturn(true);
            nrMock.when(() -> NewRelicSecurity.getAgent().getSecurityMetaData()).thenReturn(new SecurityMetaData());
            Assertions.assertFalse(IOStreamHelper.processRequestReaderHookData(null));
            nrMock.clearInvocations();
            nrMock.reset();
        }
    }
    @Test
    public void processRequestReaderHookDataTest3(){
        try (MockedStatic<NewRelicSecurity> nrMock = Mockito.mockStatic(NewRelicSecurity.class, Answers.RETURNS_DEEP_STUBS)) {
            nrMock.when(() -> NewRelicSecurity.isHookProcessingActive()).thenReturn(true);
            HashSet<Integer> set = new HashSet<>(); set.add(hashCode());
            SecurityMetaData metaData = new SecurityMetaData();
            metaData.addCustomAttribute("REQUEST_READER_HASH", set);
            nrMock.when(() -> NewRelicSecurity.getAgent().getSecurityMetaData()).thenReturn(metaData);
            Assertions.assertTrue(IOStreamHelper.processRequestReaderHookData(hashCode()));
            nrMock.clearInvocations();
            nrMock.reset();
        }
    }

    @Test
    public void processResponseWriterHookDataTest(){
        Assertions.assertFalse(IOStreamHelper.processResponseWriterHookData(null));
    }
    @Test
    public void processResponseWriterHookDataTest1(){
        try (MockedStatic<NewRelicSecurity> nrMock = Mockito.mockStatic(NewRelicSecurity.class, Answers.RETURNS_DEEP_STUBS)) {
            nrMock.when(() -> NewRelicSecurity.isHookProcessingActive()).thenReturn(true);
            Assertions.assertFalse(IOStreamHelper.processResponseWriterHookData(null));
            nrMock.clearInvocations();
            nrMock.reset();
        }
    }
    @Test
    public void processResponseWriterHookDataTest2(){
        try (MockedStatic<NewRelicSecurity> nrMock = Mockito.mockStatic(NewRelicSecurity.class, Answers.RETURNS_DEEP_STUBS)) {
            nrMock.when(() -> NewRelicSecurity.isHookProcessingActive()).thenReturn(true);
            nrMock.when(() -> NewRelicSecurity.getAgent().getSecurityMetaData()).thenReturn(new SecurityMetaData());
            Assertions.assertFalse(IOStreamHelper.processResponseWriterHookData(null));
            nrMock.clearInvocations();
            nrMock.reset();
        }
    }
    @Test
    public void processResponseWriterHookDataTest3(){
        try (MockedStatic<NewRelicSecurity> nrMock = Mockito.mockStatic(NewRelicSecurity.class, Answers.RETURNS_DEEP_STUBS)) {
            nrMock.when(() -> NewRelicSecurity.isHookProcessingActive()).thenReturn(true);
            HashSet<Integer> set = new HashSet<>(); set.add(hashCode());
            SecurityMetaData metaData = new SecurityMetaData();
            metaData.addCustomAttribute("RESPONSE_WRITER_HASH", set);
            nrMock.when(() -> NewRelicSecurity.getAgent().getSecurityMetaData()).thenReturn(metaData);
            Assertions.assertTrue(IOStreamHelper.processResponseWriterHookData(hashCode()));
            nrMock.clearInvocations();
            nrMock.reset();
        }
    }

    @Test
    public void processResponseOutputStreamHookDataTest(){
        Assertions.assertFalse(IOStreamHelper.processResponseOutputStreamHookData(null));
    }
    @Test
    public void processResponseOutputStreamHookDataTest1(){
        try (MockedStatic<NewRelicSecurity> nrMock = Mockito.mockStatic(NewRelicSecurity.class, Answers.RETURNS_DEEP_STUBS)) {
            nrMock.when(() -> NewRelicSecurity.isHookProcessingActive()).thenReturn(true);
            Assertions.assertFalse(IOStreamHelper.processResponseOutputStreamHookData(null));
            nrMock.clearInvocations();
            nrMock.reset();
        }
    }
    @Test
    public void processResponseOutputStreamHookDataTest2(){
        try (MockedStatic<NewRelicSecurity> nrMock = Mockito.mockStatic(NewRelicSecurity.class, Answers.RETURNS_DEEP_STUBS)) {
            nrMock.when(() -> NewRelicSecurity.isHookProcessingActive()).thenReturn(true);
            nrMock.when(() -> NewRelicSecurity.getAgent().getSecurityMetaData()).thenReturn(new SecurityMetaData());
            Assertions.assertFalse(IOStreamHelper.processResponseOutputStreamHookData(null));
            nrMock.clearInvocations();
            nrMock.reset();
        }
    }
    @Test
    public void processResponseOutputStreamHookDataTest3(){
        try (MockedStatic<NewRelicSecurity> nrMock = Mockito.mockStatic(NewRelicSecurity.class, Answers.RETURNS_DEEP_STUBS)) {
            nrMock.when(() -> NewRelicSecurity.isHookProcessingActive()).thenReturn(true);
            HashSet<Integer> set = new HashSet<>(); set.add(hashCode());
            SecurityMetaData metaData = new SecurityMetaData();
            metaData.addCustomAttribute("RESPONSE_OUTPUTSTREAM_HASH", set);
            nrMock.when(() -> NewRelicSecurity.getAgent().getSecurityMetaData()).thenReturn(metaData);
            Assertions.assertTrue(IOStreamHelper.processResponseOutputStreamHookData(hashCode()));
            nrMock.clearInvocations();
            nrMock.reset();
        }
    }

}
