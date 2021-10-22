package com.k2cybersecurity.instrumentator.custom;

import org.apache.commons.lang3.StringUtils;

import java.util.concurrent.Semaphore;

public class ThreadLocalTransformationLock {

    private Semaphore lock;

    private String takenBy;

    private static ThreadLocal<ThreadLocalTransformationLock> instance = new ThreadLocal<ThreadLocalTransformationLock>() {
        @Override
        protected ThreadLocalTransformationLock initialValue() {
            return new ThreadLocalTransformationLock();
        }
    };

    private ThreadLocalTransformationLock() {
        lock = new Semaphore(1);
    }

    public static ThreadLocalTransformationLock getInstance() {
        return instance.get();
    }

    public void acquire(String typeName) {
        if (!isAcquired()) {
            lock.tryAcquire();
            this.takenBy = typeName;
        }
    }

    public void release(String typeName) {
        if (StringUtils.equals(this.takenBy, typeName)) {
            lock.release();
            this.takenBy = StringUtils.EMPTY;
        }
    }

    public boolean isAcquired() {
        return lock.availablePermits() == 0;
    }
}
