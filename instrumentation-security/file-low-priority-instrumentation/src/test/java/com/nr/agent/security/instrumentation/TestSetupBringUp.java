package com.nr.agent.security.instrumentation;

import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.util.ArrayList;
import java.util.List;

public class TestSetupBringUp {
    public static void bringUp() {
        try {
            List<Class> toReTransform = new ArrayList<>();

            // java.io.FileInputStream
            SecurityInstrumentationTestRunner.instrumentation.retransformClasses(FileInputStream.class, FileOutputStream.class);

            // java.io.FileSystem and alike
            Class<?> fileSystemClass = Class.forName("java.io.FileSystem");
            toReTransform.add(fileSystemClass);

            Class<?> unixFileSystemClass = Class.forName("java.io.UnixFileSystem");
            toReTransform.add(unixFileSystemClass);

            toReTransform.add(File.class);

            SecurityInstrumentationTestRunner.instrumentation.retransformClasses(toReTransform.toArray(new Class<?>[0]));
        } catch (Throwable e) {
            e.printStackTrace();
        }
    }
}
