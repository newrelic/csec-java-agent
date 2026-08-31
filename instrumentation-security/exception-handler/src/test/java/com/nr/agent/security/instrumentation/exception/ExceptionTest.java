package com.nr.agent.security.instrumentation.exception;

import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = "java.lang.")
public class ExceptionTest {

    @Test
    // In this case single uncaughtException is invoked and therefore single Application Runtime error will be reported
    public void testReportApplicationRuntimeError() {
        Exception e = new Exception();
        Thread.UncaughtExceptionHandler uncaughtException = new Thread.UncaughtExceptionHandler() {
            @Override
            public void uncaughtException(Thread t, Throwable e) {
                e.printStackTrace();
            }
        };
        uncaughtException.uncaughtException(Thread.currentThread(), e);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        Assert.assertFalse(introspector.getApplicationRuntimeError().isEmpty());
        Assert.assertEquals(introspector.getApplicationRuntimeError().get(0), e);
    }

    @Test
    // In this case no uncaughtException is invoked and no Application Runtime error will be reported
    public void testReportNoApplicationRuntimeError() {
        Exception e = new Exception();
        Thread.UncaughtExceptionHandler uncaughtException = new Thread.UncaughtExceptionHandler() {
            @Override
            public void uncaughtException(Thread t, Throwable e) {
                e.printStackTrace();
            }
        };

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        Assert.assertTrue(introspector.getApplicationRuntimeError().isEmpty());
    }

    @Test
    // In this case multiple uncaughtExceptions are invoked and therefore multiple Application Runtime errors will be reported
    public void testReportApplicationRuntimeErrors() {
        Exception e = new Exception();

        Thread.UncaughtExceptionHandler uncaughtException = new Thread.UncaughtExceptionHandler() {
            @Override
            public void uncaughtException(Thread t, Throwable e) {
                e.printStackTrace();
            }
        };
        uncaughtException.uncaughtException(Thread.currentThread(), e);

        Exception e1 = new Exception();
        uncaughtException.uncaughtException(Thread.currentThread(), e1);

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        Assert.assertFalse(introspector.getApplicationRuntimeError().isEmpty());
        Assert.assertEquals(introspector.getApplicationRuntimeError().get(0), e);
        Assert.assertEquals(introspector.getApplicationRuntimeError().get(1), e1);
    }
}
