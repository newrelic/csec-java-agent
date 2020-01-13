package com.k2cybersecurity.instrumentator.custom;

import java.util.concurrent.Semaphore;

public class ThreadLocalHTTPServiceLock {

    private Semaphore lock;

    private Object takenBy;

    private static ThreadLocal<ThreadLocalHTTPServiceLock> instance = new ThreadLocal<ThreadLocalHTTPServiceLock>() {
        @Override
        protected ThreadLocalHTTPServiceLock initialValue() {
            return new ThreadLocalHTTPServiceLock();
        }
    };

    private ThreadLocalHTTPServiceLock() {
        lock = new Semaphore(1);
    }

    public static ThreadLocalHTTPServiceLock getInstance() {
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
        if (this.takenBy !=null && takenBy !=null && this.takenBy.hashCode() == takenBy.hashCode()) {
            lock.release();
            this.takenBy = null;
        }
    }

    public boolean isAcquired() {
        return lock.availablePermits() == 0;
    }

    public boolean isAcquired(Object takenBy) {
        if(this.takenBy != null) {
            return this.takenBy.equals(takenBy) && isAcquired();
        } else {
            return false;
        }
    }


    public void resetLock() {
        lock = new Semaphore(1);
        takenBy = null;
    }

    public Object isTakenBy() {
        return takenBy;
    }
}
