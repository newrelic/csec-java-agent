package com.newrelic.agent.security.instrumentator.custom;

import java.util.concurrent.Semaphore;

public class ThreadLocalOperationLock {

    private Semaphore lock;

    private static ThreadLocal<ThreadLocalOperationLock> instance = new ThreadLocal<ThreadLocalOperationLock>() {
        @Override
        protected ThreadLocalOperationLock initialValue() {
            return new ThreadLocalOperationLock();
        }
    };

    private ThreadLocalOperationLock() {
        lock = new Semaphore(1);
    }

    public static ThreadLocalOperationLock getInstance() {
        return instance.get();
    }

    public void acquire() {
        try {
            lock.acquire();
        } catch (InterruptedException e) {
        }
    }

    public void release() {
        lock.release();
    }

    public boolean isAcquired() {
        return lock.availablePermits() == 0;
    }
}
