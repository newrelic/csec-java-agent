package com.nr.instrumentation.security.javaio;

import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;

import java.io.BufferedReader;
import java.io.FileOutputStream;
import java.io.InputStreamReader;
import java.io.Reader;

public class TestSetupBringUp {
    public static void bringUp() {
        try {
            SecurityInstrumentationTestRunner.instrumentation.retransformClasses(FileOutputStream.class, BufferedReader.class, InputStreamReader.class,
                    Reader.class);
        } catch (Throwable e) {
            e.printStackTrace();
        }
    }
}
