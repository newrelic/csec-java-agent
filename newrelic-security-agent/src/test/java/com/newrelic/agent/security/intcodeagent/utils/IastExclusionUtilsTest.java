package com.newrelic.agent.security.intcodeagent.utils;

import org.junit.Assert;
import org.junit.Test;

public class IastExclusionUtilsTest {

    @Test
    public void skippedTraceTest() {
        Assert.assertFalse(IastExclusionUtils.getInstance().skippedTrace(""));
        Assert.assertFalse(IastExclusionUtils.getInstance().skippedTrace("123"));
    }

    @Test
    public void skipTraceApiTest() {
        Assert.assertFalse(IastExclusionUtils.getInstance().skipTraceApi(""));
        Assert.assertFalse(IastExclusionUtils.getInstance().skipTraceApi("/api"));
    }

    @Test
    public void addEncounteredTraceTest() {
        IastExclusionUtils.getInstance().registerSkippedTrace("trace-id");
        IastExclusionUtils.getInstance().addEncounteredTrace("trace-id", "operation-id");
        Assert.assertTrue(IastExclusionUtils.getInstance().skipTraceApi("operation-id"));
    }

    @Test
    public void addEncounteredTrace1Test() {
        IastExclusionUtils.getInstance().addEncounteredTrace("trace-id", "operation-id");
        Assert.assertTrue(IastExclusionUtils.getInstance().skipTraceApi("operation-id"));
    }
}
