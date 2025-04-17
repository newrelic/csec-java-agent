package com.newrelic.api.agent.security.instrumentation.helpers;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.schema.HttpResponse;
import com.newrelic.api.agent.security.schema.SecurityMetaData;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Answers;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import java.util.Collections;
import java.util.HashSet;

public class IOSTreamHelperTest {
    @Test
    public void processRequestReaderHookDataTest() {
        Assertions.assertFalse(IOStreamHelper.processRequestReaderHookData(null));
    }

    @Test
    public void processRequestReaderHookDataTest1() {
        MockedStatic<NewRelicSecurity> nrMock = Mockito.mockStatic(NewRelicSecurity.class, Answers.RETURNS_DEEP_STUBS);
        try {
            nrMock.when(() -> NewRelicSecurity.isHookProcessingActive()).thenReturn(true);
            Assertions.assertFalse(IOStreamHelper.processRequestReaderHookData(null));
        } finally {
            GrpcHelperTest.clearMockitoInvocation(nrMock);
        }
    }

    @Test
    public void processRequestReaderHookDataTest2() {
        MockedStatic<NewRelicSecurity> nrMock = Mockito.mockStatic(NewRelicSecurity.class, Answers.RETURNS_DEEP_STUBS);
        try {
            nrMock.when(() -> NewRelicSecurity.isHookProcessingActive()).thenReturn(true);
            nrMock.when(() -> NewRelicSecurity.getAgent().getSecurityMetaData()).thenReturn(new SecurityMetaData());
            Assertions.assertFalse(IOStreamHelper.processRequestReaderHookData(null));
        } finally {
            GrpcHelperTest.clearMockitoInvocation(nrMock);
        }
    }

    @Test
    public void processRequestReaderHookDataTest3() {
        MockedStatic<NewRelicSecurity> nrMock = Mockito.mockStatic(NewRelicSecurity.class, Answers.RETURNS_DEEP_STUBS);
        try {
            nrMock.when(() -> NewRelicSecurity.isHookProcessingActive()).thenReturn(true);
            HashSet<Integer> set = new HashSet<>();
            set.add(hashCode());
            SecurityMetaData metaData = new SecurityMetaData();
            metaData.addCustomAttribute("REQUEST_READER_HASH", set);
            nrMock.when(() -> NewRelicSecurity.getAgent().getSecurityMetaData()).thenReturn(metaData);
            Assertions.assertTrue(IOStreamHelper.processRequestReaderHookData(hashCode()));
        } finally {
            GrpcHelperTest.clearMockitoInvocation(nrMock);
        }
    }

    @Test
    public void processResponseWriterHookDataTest() {
        Assertions.assertFalse(IOStreamHelper.processResponseWriterHookData(null));
    }

    @Test
    public void processResponseWriterHookDataTest1() {
        MockedStatic<NewRelicSecurity> nrMock = Mockito.mockStatic(NewRelicSecurity.class, Answers.RETURNS_DEEP_STUBS);
        try {
            nrMock.when(() -> NewRelicSecurity.isHookProcessingActive()).thenReturn(true);
            Assertions.assertFalse(IOStreamHelper.processResponseWriterHookData(null));
        } finally {
            GrpcHelperTest.clearMockitoInvocation(nrMock);
        }
    }

    @Test
    public void processResponseWriterHookDataTest2() {
        MockedStatic<NewRelicSecurity> nrMock = Mockito.mockStatic(NewRelicSecurity.class, Answers.RETURNS_DEEP_STUBS);
        try {
            nrMock.when(() -> NewRelicSecurity.isHookProcessingActive()).thenReturn(true);
            nrMock.when(() -> NewRelicSecurity.getAgent().getSecurityMetaData()).thenReturn(new SecurityMetaData());
            Assertions.assertFalse(IOStreamHelper.processResponseWriterHookData(null));
        } finally {
            GrpcHelperTest.clearMockitoInvocation(nrMock);
        }
    }

    @Test
    public void processResponseWriterHookDataTest3() {
        MockedStatic<NewRelicSecurity> nrMock = Mockito.mockStatic(NewRelicSecurity.class, Answers.RETURNS_DEEP_STUBS);
        try {
            nrMock.when(() -> NewRelicSecurity.isHookProcessingActive()).thenReturn(true);
            HashSet<Integer> set = new HashSet<>();
            set.add(hashCode());
            SecurityMetaData metaData = new SecurityMetaData();
            metaData.addCustomAttribute("RESPONSE_WRITER_HASH", set);
            nrMock.when(() -> NewRelicSecurity.getAgent().getSecurityMetaData()).thenReturn(metaData);
            Assertions.assertTrue(IOStreamHelper.processResponseWriterHookData(hashCode()));
        } finally {
            GrpcHelperTest.clearMockitoInvocation(nrMock);
        }
    }

    @Test
    public void processResponseOutputStreamHookDataTest() {
        Assertions.assertFalse(IOStreamHelper.processResponseOutputStreamHookData(null));
    }

    @Test
    public void processResponseOutputStreamHookDataTest1() {
        MockedStatic<NewRelicSecurity> nrMock = Mockito.mockStatic(NewRelicSecurity.class, Answers.RETURNS_DEEP_STUBS);
        try {
            nrMock.when(() -> NewRelicSecurity.isHookProcessingActive()).thenReturn(true);
            Assertions.assertFalse(IOStreamHelper.processResponseOutputStreamHookData(null));
        } finally {
            GrpcHelperTest.clearMockitoInvocation(nrMock);
        }
    }

    @Test
    public void processResponseOutputStreamHookDataTest2() {
        MockedStatic<NewRelicSecurity> nrMock = Mockito.mockStatic(NewRelicSecurity.class, Answers.RETURNS_DEEP_STUBS);
        try {
            nrMock.when(() -> NewRelicSecurity.isHookProcessingActive()).thenReturn(true);
            nrMock.when(() -> NewRelicSecurity.getAgent().getSecurityMetaData()).thenReturn(new SecurityMetaData());
            Assertions.assertFalse(IOStreamHelper.processResponseOutputStreamHookData(null));
        } finally {
            GrpcHelperTest.clearMockitoInvocation(nrMock);
        }
    }

    @Test
    public void processResponseOutputStreamHookDataTest3() {
        MockedStatic<NewRelicSecurity> nrMock = Mockito.mockStatic(NewRelicSecurity.class, Answers.RETURNS_DEEP_STUBS);
        try {
            nrMock.when(() -> NewRelicSecurity.isHookProcessingActive()).thenReturn(true);
            HashSet<Integer> set = new HashSet<>();
            set.add(hashCode());
            SecurityMetaData metaData = new SecurityMetaData();
            metaData.addCustomAttribute("RESPONSE_OUTPUTSTREAM_HASH", set);
            nrMock.when(() -> NewRelicSecurity.getAgent().getSecurityMetaData()).thenReturn(metaData);
            Assertions.assertTrue(IOStreamHelper.processResponseOutputStreamHookData(hashCode()));
        } finally {
            GrpcHelperTest.clearMockitoInvocation(nrMock);
        }
    }

    @Test
    public void preprocessSecurityHookTest() {
        MockedStatic<NewRelicSecurity> nrMock = Mockito.mockStatic(NewRelicSecurity.class, Answers.RETURNS_DEEP_STUBS);
        try {
            nrMock.when(NewRelicSecurity.getAgent().getSecurityMetaData()::getResponse).thenReturn(Mockito.mock(HttpResponse.class));
            IOStreamHelper.preprocessSecurityHook("data".getBytes(), 0, 1);
        } finally {
            GrpcHelperTest.clearMockitoInvocation(nrMock);
        }
    }

}
