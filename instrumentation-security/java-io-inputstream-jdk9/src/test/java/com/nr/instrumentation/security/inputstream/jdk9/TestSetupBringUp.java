package com.nr.instrumentation.security.inputstream.jdk9;

import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

public class TestSetupBringUp {
    public static void bringUp() {
        try {
            SecurityInstrumentationTestRunner.instrumentation.retransformClasses(InputStream.class,
                    FileInputStream.class, ByteArrayInputStream.class);

            List<Class> toReTransform = new ArrayList<>();

            Class<?> channelInputStream = Class.forName("sun.nio.ch.ChannelInputStream");
            toReTransform.add(channelInputStream);

            SecurityInstrumentationTestRunner.instrumentation.retransformClasses(toReTransform.toArray(new Class<?>[0]));
        } catch (Throwable e) {
            e.printStackTrace();
        }
    }
}
