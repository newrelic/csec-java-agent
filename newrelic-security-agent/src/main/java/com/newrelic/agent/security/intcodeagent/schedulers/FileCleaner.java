package com.newrelic.agent.security.intcodeagent.schedulers;

import com.newrelic.agent.security.AgentInfo;
import com.newrelic.agent.security.instrumentator.os.OSVariables;
import com.newrelic.agent.security.instrumentator.os.OsVariablesInstance;
import com.newrelic.agent.security.intcodeagent.filelogging.FileLoggerThreadPool;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import com.newrelic.api.agent.security.instrumentation.helpers.ServletHelper;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.filefilter.AgeFileFilter;
import org.apache.commons.io.filefilter.DirectoryFileFilter;
import org.apache.commons.lang3.StringUtils;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Paths;
import java.time.Instant;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

public class FileCleaner {

    private static OSVariables osVariables = OsVariablesInstance.getInstance().getOsVariables();

    private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

    private static ScheduledFuture future;

    public static final String FILE_CLEANER_INVOKED_INITIATING_TEMP_FILE_DIRECTORY_CLEANUP = "File cleaner invoked. Initiating temp file & directory cleanup.";
    private static Runnable runnable = new Runnable() {

        @Override
        public void run() {
            AgentInfo.getInstance().getJaHealthCheck().getSchedulerRuns().incrementIastFileCleaner();
            long delay = Instant.now().toEpochMilli() - TimeUnit.MINUTES.toMillis(2);
            logger.log(LogLevel.INFO, FILE_CLEANER_INVOKED_INITIATING_TEMP_FILE_DIRECTORY_CLEANUP, FileCleaner.class.getName());
            if(StringUtils.isBlank(osVariables.getTmpDirectory())) {
                return;
            }
            FileUtils.iterateFiles(new File(osVariables.getTmpDirectory()), new AgeFileFilter(delay), DirectoryFileFilter.INSTANCE).forEachRemaining( file -> {
                FileUtils.deleteQuietly(file);
            });

            for (String file : ServletHelper.getFilesToRemove()) {
                try {
                    if(Files.isSameFile(Paths.get(file), Paths.get(osVariables.getTmpDirectory()))){
                        continue;
                    }
                    long age = delay - Files.getLastModifiedTime(Paths.get(file)).toMillis();
                    if(age > 0){
                        FileUtils.deleteQuietly(new File(file));
                    }
                } catch (IOException | InvalidPathException e) {
                }
            }
        }
    };

    public static void scheduleNewTask() {
        future = SchedulerHelper.getInstance().scheduleTmpFileCleanup(runnable, 2, 2, TimeUnit.MINUTES);
    }

    public static boolean cancelTask() {
        if (future == null) {
            return true;
        }
        logger.log(LogLevel.INFO, "Cancel current task of File cleaner Schedule", FileCleaner.class.getName());
        future.cancel(true);
        return true;
    }

}
