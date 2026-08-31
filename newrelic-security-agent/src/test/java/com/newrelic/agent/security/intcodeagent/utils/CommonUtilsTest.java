package com.newrelic.agent.security.intcodeagent.utils;

import com.newrelic.agent.security.util.IUtilConstants;
import org.junit.Test;

import java.io.IOException;
import java.nio.file.Paths;
import java.util.UUID;

public class CommonUtilsTest {

    @Test(expected = IOException.class)
    public void forceMkdirsTest() throws IOException {
        CommonUtils.forceMkdirs(Paths.get(""), IUtilConstants.DIRECTORY_PERMISSION);
    }

    @Test
    public void forceMkdirs1Test() throws IOException {
        CommonUtils.forceMkdirs(Paths.get(String.format("/tmp/tmp%s/", UUID.randomUUID())), IUtilConstants.DIRECTORY_PERMISSION);
    }
}
