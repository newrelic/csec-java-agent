package com.newrelic.agent.security.intcodeagent.schedulers;

import com.newrelic.agent.security.instrumentator.os.OsVariablesInstance;
import org.apache.commons.io.FileUtils;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.Test;

import java.io.File;

public class FileCleanerTest {
    private final static File TMP_DIR = new File(OsVariablesInstance.getInstance().getOsVariables().getTmpDirectory());

    @AfterClass
    public static void cleanUp() {
        FileUtils.deleteQuietly(TMP_DIR);
    }
    @Test
    public void tmpFileCleanupCancel() {
        File tmp = new File(TMP_DIR.toURI());
        tmp.mkdirs();
        FileCleaner.scheduleNewTask();
        Assert.assertTrue(FileCleaner.cancelTask());
        Assert.assertTrue(tmp.exists());
    }
}
