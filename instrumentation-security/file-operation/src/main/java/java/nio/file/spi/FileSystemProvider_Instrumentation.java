/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package java.nio.file.spi;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.FileHelper;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.exceptions.NewRelicSecurityException;
import com.newrelic.api.agent.security.schema.operation.FileOperation;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.channels.AsynchronousFileChannel;
import java.nio.channels.FileChannel;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.*;
import java.nio.file.attribute.FileAttribute;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutorService;

@Weave(type = MatchType.BaseClass, originalName = "java.nio.file.spi.FileSystemProvider")
public abstract class FileSystemProvider_Instrumentation {

    public void copy(Path source, Path target, CopyOption... options)
            throws IOException {
        boolean isFileLockAcquired = acquireFileLockIfPossible();
        AbstractOperation operation = null;
        if(isFileLockAcquired) {
            operation = preprocessSecurityHook(FileHelper.FILE_COPY, source, target);
        }
        try {
            Weaver.callOriginal();
        } finally {
            if (!isFileLockAcquired) {
                releaseFileLock();
            }
        }
        registerExitOperation(operation, isFileLockAcquired);
    }

    public InputStream newInputStream(Path path, OpenOption... options)
            throws IOException
    {
        boolean isFileLockAcquired = acquireFileLockIfPossible();
        AbstractOperation operation = null;
        InputStream returnData;
        if(isFileLockAcquired) {
            operation = preprocessSecurityHook(FileHelper.NEW_INPUT_STREAM, path);
        }
        try {
            returnData = Weaver.callOriginal();
        } finally {
            if (!isFileLockAcquired) {
                releaseFileLock();
            }
        }
        registerExitOperation(operation, isFileLockAcquired);
        return returnData;
    }

    public OutputStream newOutputStream(Path path, OpenOption... options)
            throws IOException
    {
        boolean isFileLockAcquired = acquireFileLockIfPossible();
        AbstractOperation operation = null;
        OutputStream returnData;
        if(isFileLockAcquired) {
            operation = preprocessSecurityHook(FileHelper.NEW_OUTPUT_STREAM, path);
        }
        try {
            returnData = Weaver.callOriginal();
        } finally {
            if (!isFileLockAcquired) {
                releaseFileLock();
            }
        }
        registerExitOperation(operation, isFileLockAcquired);
        return returnData;
    }

    public FileChannel newFileChannel(Path path,
                                      Set<? extends OpenOption> options,
                                      FileAttribute<?>... attrs)
            throws IOException
    {
        boolean isFileLockAcquired = acquireFileLockIfPossible();
        AbstractOperation operation = null;
        FileChannel returnData;
        if(isFileLockAcquired) {
            operation = preprocessSecurityHook(FileHelper.NEW_FILE_CHANNEL, path);
        }
        try {
            returnData = Weaver.callOriginal();
        } finally {
            if (!isFileLockAcquired) {
                releaseFileLock();
            }
        }
        registerExitOperation(operation, isFileLockAcquired);
        return returnData;
    }

    public AsynchronousFileChannel newAsynchronousFileChannel(Path path,
                                                              Set<? extends OpenOption> options,
                                                              ExecutorService executor,
                                                              FileAttribute<?>... attrs)
            throws IOException
    {
        boolean isFileLockAcquired = acquireFileLockIfPossible();
        AbstractOperation operation = null;
        AsynchronousFileChannel returnData;
        if(isFileLockAcquired) {
            operation = preprocessSecurityHook(FileHelper.NEW_ASYNCHRONOUS_FILE_CHANNEL, path);
        }
        try {
            returnData = Weaver.callOriginal();
        } finally {
            if (!isFileLockAcquired) {
                releaseFileLock();
            }
        }
        registerExitOperation(operation, isFileLockAcquired);
        return returnData;
    }

    public SeekableByteChannel newByteChannel(Path path,
                                                       Set<? extends OpenOption> options, FileAttribute<?>... attrs) throws IOException
    {
        boolean isFileLockAcquired = acquireFileLockIfPossible();
        AbstractOperation operation = null;
        SeekableByteChannel returnData;
        if(isFileLockAcquired) {
            operation = preprocessSecurityHook(FileHelper.NEW_BYTE_CHANNEL, path);
        }
        try {
            returnData = Weaver.callOriginal();
        } finally {
            if (!isFileLockAcquired) {
                releaseFileLock();
            }
        }
        registerExitOperation(operation, isFileLockAcquired);
        return returnData;
    }

    public DirectoryStream<Path> newDirectoryStream(Path dir,
                                                             DirectoryStream.Filter<? super Path> filter) throws IOException{
        boolean isFileLockAcquired = acquireFileLockIfPossible();
        AbstractOperation operation = null;
        DirectoryStream<Path> returnData;
        if(isFileLockAcquired) {
            operation = preprocessSecurityHook(FileHelper.NEW_DIRECTORY_STREAM, dir);
        }
        try {
            returnData = Weaver.callOriginal();
        } finally {
            if (!isFileLockAcquired) {
                releaseFileLock();
            }
        }
        registerExitOperation(operation, isFileLockAcquired);
        return returnData;
    }

    public void createDirectory(Path dir, FileAttribute<?>... attrs)
            throws IOException {
        boolean isFileLockAcquired = acquireFileLockIfPossible();
        AbstractOperation operation = null;
        if(isFileLockAcquired) {
            operation = preprocessSecurityHook(FileHelper.CREATE_DIRECTORY, dir);
        }
        try {
            Weaver.callOriginal();
        } finally {
            if (!isFileLockAcquired) {
                releaseFileLock();
            }
        }
        registerExitOperation(operation, isFileLockAcquired);
    }

    public void createSymbolicLink(Path link, Path target, FileAttribute<?>... attrs)
            throws IOException
    {
        boolean isFileLockAcquired = acquireFileLockIfPossible();
        AbstractOperation operation = null;
        if(isFileLockAcquired) {
            operation = preprocessSecurityHook(FileHelper.CREATE_SYMBOLIC_LINK, link, target);
        }
        try {
            Weaver.callOriginal();
        } finally {
            if (!isFileLockAcquired) {
                releaseFileLock();
            }
        }
        registerExitOperation(operation, isFileLockAcquired);
    }

    public void createLink(Path link, Path existing) throws IOException {
        boolean isFileLockAcquired = acquireFileLockIfPossible();
        AbstractOperation operation = null;
        if(isFileLockAcquired) {
            operation = preprocessSecurityHook(FileHelper.CREATE_LINK, link, existing);
        }
        try {
            Weaver.callOriginal();
        } finally {
            if (!isFileLockAcquired) {
                releaseFileLock();
            }
        }
        registerExitOperation(operation, isFileLockAcquired);
    }

    public void delete(Path path) throws IOException {
        boolean isFileLockAcquired = acquireFileLockIfPossible();
        AbstractOperation operation = null;
        if(isFileLockAcquired) {
            operation = preprocessSecurityHook(FileHelper.DELETE, path);
        }
        try {
            Weaver.callOriginal();
        } finally {
            if (!isFileLockAcquired) {
                releaseFileLock();
            }
        }
        registerExitOperation(operation, isFileLockAcquired);
    }

    public boolean deleteIfExists(Path path) throws IOException {
        boolean isFileLockAcquired = acquireFileLockIfPossible();
        AbstractOperation operation = null;
        boolean returnData;
        if(isFileLockAcquired) {
            operation = preprocessSecurityHook(FileHelper.DELETE_IF_EXISTS, path);
        }
        try {
            returnData = Weaver.callOriginal();
        } finally {
            if (!isFileLockAcquired) {
                releaseFileLock();
            }
        }
        registerExitOperation(operation, isFileLockAcquired);
        return returnData;
    }

    public void move(Path source, Path target, CopyOption... options)
            throws IOException {
        boolean isFileLockAcquired = acquireFileLockIfPossible();
        AbstractOperation operation = null;
        if(isFileLockAcquired) {
            operation = preprocessSecurityHook(FileHelper.MOVE, source, target);
        }
        try {
            Weaver.callOriginal();
        } finally {
            if (!isFileLockAcquired) {
                releaseFileLock();
            }
        }
        registerExitOperation(operation, isFileLockAcquired);
    }

    public void setAttribute(Path path, String attribute,
                                      Object value, LinkOption... options)
            throws IOException {
        boolean isFileLockAcquired = acquireFileLockIfPossible();
        AbstractOperation operation = null;
        if(isFileLockAcquired) {
            operation = preprocessSecurityHook(FileHelper.SET_ATTRIBUTE, path);
        }
        try {
            Weaver.callOriginal();
        } finally {
            if (!isFileLockAcquired) {
                releaseFileLock();
            }
        }
        registerExitOperation(operation, isFileLockAcquired);
    }
    private void releaseFileLock() {
        try {
            FileHelper.releaseFileLock();
        } catch (Throwable ignored){}
    }

    private boolean acquireFileLockIfPossible() {
        try {
            return FileHelper.acquireFileLockIfPossible();
        } catch (Throwable ignored){}
        return false;
    }


    private void registerExitOperation(AbstractOperation operation, boolean isFileLockAcquired) {
        try {
            if (operation == null || !isFileLockAcquired || !NewRelicSecurity.isHookProcessingActive() || NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty()) {
                return;
            }
            NewRelicSecurity.getAgent().registerExitEvent(operation);
        } catch (Throwable ignored){}
    }

    private AbstractOperation preprocessSecurityHook(String methodName, Path... filename) {
        try {
            if (!NewRelicSecurity.isHookProcessingActive() || NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty()) {
                return null;
            }

            List<String> fileNames = new ArrayList<>();
            for (Path path : filename) {
                if(path != null){
                    String absolutePath = path.toAbsolutePath().toString();
                    fileNames.add(absolutePath);
                    FileHelper.createEntryOfFileIntegrity(absolutePath, this.getClass().getName(), methodName);
                }
            }

            FileOperation operation = new FileOperation(this.getClass().getName(), methodName, false, fileNames);
            NewRelicSecurity.getAgent().registerOperation(operation);
            return operation;
        } catch (Throwable e) {
            if (e instanceof NewRelicSecurityException) {
                e.printStackTrace();
                throw e;
            }
        }
        return null;
    }
}
