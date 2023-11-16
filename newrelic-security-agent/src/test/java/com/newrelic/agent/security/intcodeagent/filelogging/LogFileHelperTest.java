package com.newrelic.agent.security.intcodeagent.filelogging;

import com.newrelic.api.agent.NewRelic;
import org.junit.Assert;
import org.junit.Test;
import org.mockito.Answers;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;

public class LogFileHelperTest {
    @Test
    public void isLoggingToStdOut() {
        Assert.assertFalse(LogFileHelper.isLoggingToStdOut());
    }
    @Test
    public void isLoggingToStdOut1() {
        try (MockedStatic<NewRelic> nrMock = Mockito.mockStatic(NewRelic.class, Answers.RETURNS_DEEP_STUBS)){
            nrMock.when(NewRelic.getAgent().getConfig().getValue(eq(LogFileHelper.LOG_FILE_NAME), any())).thenReturn(LogFileHelper.STDOUT);

            Assert.assertTrue(LogFileHelper.isLoggingToStdOut());
            nrMock.reset();
            nrMock.clearInvocations();
        }
    }
    @Test
    public void logFileCount() {
        Assert.assertEquals(1, LogFileHelper.logFileCount());
    }
    @Test
    public void logFileCount1() {
        try (MockedStatic<NewRelic> nrMock = Mockito.mockStatic(NewRelic.class, Answers.RETURNS_DEEP_STUBS)){
            nrMock.when(NewRelic.getAgent().getConfig().getValue(eq(LogFileHelper.LOG_FILE_COUNT), any())).thenReturn(2);

            Assert.assertEquals(2, LogFileHelper.logFileCount());
            nrMock.reset();
            nrMock.clearInvocations();
        }
    }
    @Test
    public void logFileLimit() {
        Assert.assertEquals(51200, LogFileHelper.logFileLimit());
    }
    @Test
    public void logFileLimit1() {
        try (MockedStatic<NewRelic> nrMock = Mockito.mockStatic(NewRelic.class, Answers.RETURNS_DEEP_STUBS)){
            nrMock.when(NewRelic.getAgent().getConfig().getValue(eq(LogFileHelper.LOG_LIMIT), any())).thenReturn(2);

            Assert.assertEquals(2, LogFileHelper.logFileLimit());
            nrMock.reset();
            nrMock.clearInvocations();
        }
    }
    @Test
    public void isDailyRollover() {
        Assert.assertFalse(LogFileHelper.isDailyRollover());
    }
    @Test
    public void isDailyRollover1() {
        try (MockedStatic<NewRelic> nrMock = Mockito.mockStatic(NewRelic.class, Answers.RETURNS_DEEP_STUBS)){
            nrMock.when(NewRelic.getAgent().getConfig().getValue(eq(LogFileHelper.LOG_DAILY), any())).thenReturn(true);

            Assert.assertTrue(LogFileHelper.isDailyRollover());
            nrMock.reset();
            nrMock.clearInvocations();
        }
    }
}
