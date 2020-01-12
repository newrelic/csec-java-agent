package com.k2cybersecurity.instrumentator.custom;

import java.util.concurrent.Semaphore;

public class ThreadLocalHTTPIOLock {

    private Semaphore lock;

    private Object takenBy;

    private static ThreadLocal<ThreadLocalHTTPIOLock> instance = new ThreadLocal<ThreadLocalHTTPIOLock>() {
        @Override
        protected ThreadLocalHTTPIOLock initialValue() {
            return new ThreadLocalHTTPIOLock();
        }
    };

    private ThreadLocalHTTPIOLock() {
        lock = new Semaphore(1);
    }

    public static ThreadLocalHTTPIOLock getInstance() {
        return instance.get();
    }

    public void acquire(Object takenBy) {
        try {
            this.takenBy = takenBy;
            lock.acquire();
        } catch (InterruptedException e) {
        }
    }

    public void release(Object takenBy) {
        if (this.takenBy == takenBy) {
            lock.release();
            this.takenBy = null;
        }
    }

    public boolean isAcquired() {
        return lock.availablePermits() == 0;
    }

    public boolean isAcquired(Object takenBy) {
        return this.takenBy == takenBy && isAcquired();
    }


    public void resetLock() {
        lock = new Semaphore(1);
        takenBy = null;
    }

    public Object isTakenBy() {
        return takenBy;
    }
}
