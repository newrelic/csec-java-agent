package com.k2cybersecurity.instrumentator.custom;

import org.apache.commons.lang3.StringUtils;

import java.util.concurrent.Semaphore;

public class ThreadLocalHTTPServiceLock {

    private Semaphore lock;

    private Object takenBy;

    private String sourceSignature = StringUtils.EMPTY;

    private String eId = StringUtils.EMPTY;

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

    public void acquire(Object takenBy, String sourceSignature, String eId) {
        try {
            this.takenBy = takenBy;
            this.sourceSignature = sourceSignature;
            this.eId = eId;

            lock.acquire();
        } catch (InterruptedException e) {
        }
    }

    public void release(Object takenBy, String sourceSignature, String eId) {
        if (this.takenBy != null && takenBy != null && this.takenBy.hashCode() == takenBy.hashCode()
                && StringUtils.equals(sourceSignature, this.sourceSignature)
                && StringUtils.equals(eId, this.eId)) {
            lock.release();
            this.takenBy = null;
            this.sourceSignature = StringUtils.EMPTY;
            this.eId = StringUtils.EMPTY;
        }
    }

    public boolean isAcquired() {
        return lock.availablePermits() == 0;
    }

    public boolean isAcquired(Object takenBy, String sourceSignature, String eId) {
        if (this.takenBy != null) {
            return this.takenBy.equals(takenBy) && isAcquired() && StringUtils.equals(sourceSignature, this.sourceSignature) && StringUtils.equals(eId, this.eId);
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

    public String isTakenBySource() {
        return sourceSignature;
    }

    public String isTakenByeId() {
        return eId;
    }


}
