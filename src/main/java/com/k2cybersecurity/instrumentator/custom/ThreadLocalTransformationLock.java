package com.k2cybersecurity.instrumentator.custom;

import java.util.concurrent.atomic.AtomicInteger;

public class ThreadLocalTransformationLock {
    private AtomicInteger counter;

    private static ThreadLocal<ThreadLocalTransformationLock> instance = new ThreadLocal<ThreadLocalTransformationLock>() {
        @Override
        protected ThreadLocalTransformationLock initialValue() {
            return new ThreadLocalTransformationLock();
        }
    };

    private ThreadLocalTransformationLock() {
        counter = new AtomicInteger(0);
    }

    public static ThreadLocalTransformationLock getInstance() {
        return instance.get();
    }

    public void acquire() {
        counter.getAndIncrement();
    }

    public void release() {
        counter.decrementAndGet();
    }

    public boolean isAcquired() {
        return counter.get() > 0;
    }
}
