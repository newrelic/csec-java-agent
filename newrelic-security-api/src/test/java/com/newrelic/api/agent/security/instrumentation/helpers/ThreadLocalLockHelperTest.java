package com.newrelic.api.agent.security.instrumentation.helpers;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class ThreadLocalLockHelperTest {

    @Test
    public void acquireLockTest() {
        Assertions.assertTrue(ThreadLocalLockHelper.acquireLock());
        Assertions.assertTrue(ThreadLocalLockHelper.isLockHeldByCurrentThread());
        Assertions.assertFalse(ThreadLocalLockHelper.acquireLock());

        ThreadLocalLockHelper.releaseLock();
        Assertions.assertFalse(ThreadLocalLockHelper.isLockHeldByCurrentThread());
    }

}
