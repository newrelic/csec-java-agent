package com.newrelic.agent.security.instrumentation.javaio;

import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.InputStream;

public class TestSetupBringUp {
    public static void bringUp() {
        try {
            SecurityInstrumentationTestRunner.instrumentation.retransformClasses(InputStream.class,
                    FileInputStream.class, ByteArrayInputStream.class, sun.nio.ch.ChannelInputStream.class);
        } catch (Throwable e) {
            e.printStackTrace();
        }
    }
}
