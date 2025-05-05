package com.newrelic.agent.security.instrumentator.utils;

import org.junit.Assert;
import org.junit.Test;

public class ExecutionIDGeneratorTest {
    @Test
    public void testGetExecutionId() {
        String executionId = ExecutionIDGenerator.getExecutionId();
        Assert.assertEquals(String.format("%d:%d",Thread.currentThread().getId(),0), executionId);

        executionId = ExecutionIDGenerator.getExecutionId();
        Assert.assertEquals(String.format("%d:%d",Thread.currentThread().getId(),1), executionId);
    }
}
