package com.nr.instrumentation.security.javanio;

import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;

import java.nio.file.FileSystems;
import java.nio.file.spi.FileSystemProvider;
import java.util.ArrayList;
import java.util.List;

public class TestSetupBringUp {
    public static void bringUp() {
        try {
            // java.io.FileInputStream
            SecurityInstrumentationTestRunner.instrumentation.retransformClasses(FileSystemProvider.class, FileSystems.class);

            List<Class> toReTransform = new ArrayList<>();

            // java.io.FileSystem and alike
            Class<?> unixFileSystemProvider = Class.forName("sun.nio.fs.UnixFileSystemProvider");
            toReTransform.add(unixFileSystemProvider);

            Class<?> bsdFileSystemProvider = Class.forName("sun.nio.fs.BsdFileSystemProvider");
            toReTransform.add(bsdFileSystemProvider);

            Class<?> macOSXFileSystemProvider = Class.forName("sun.nio.fs.MacOSXFileSystemProvider");
            toReTransform.add(macOSXFileSystemProvider);

            Class<?> abstractFileSystemProvider = Class.forName("sun.nio.fs.AbstractFileSystemProvider");
            toReTransform.add(abstractFileSystemProvider);

            SecurityInstrumentationTestRunner.instrumentation.retransformClasses(toReTransform.toArray(new Class<?>[0]));
        } catch (Throwable e) {
            e.printStackTrace();
        }
    }
}
