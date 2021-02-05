package com.k2cybersecurity.instrumentator.custom;

import org.apache.commons.lang3.StringUtils;

import java.util.concurrent.Semaphore;

public class ThreadLocalSSRFLock {

    private Semaphore lock;

    private Object takenBy;

    private String sourceSignature = StringUtils.EMPTY;

    private String eId = StringUtils.EMPTY;

    private String url = StringUtils.EMPTY;

    private static ThreadLocal<ThreadLocalSSRFLock> instance = new ThreadLocal<ThreadLocalSSRFLock>() {
        @Override
        protected ThreadLocalSSRFLock initialValue() {
            return new ThreadLocalSSRFLock();
        }
    };

    private ThreadLocalSSRFLock() {
        lock = new Semaphore(1);
    }

    public static ThreadLocalSSRFLock getInstance() {
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
            ThreadLocalSSRFMap.getInstance().cleanUp();
            this.takenBy = null;
            this.sourceSignature = StringUtils.EMPTY;
            this.eId = StringUtils.EMPTY;
            url = StringUtils.EMPTY;
        }
    }

    public boolean isAcquired() {
        return lock.availablePermits() == 0;
    }

    public boolean isAcquired(Object takenBy, String sourceSignature, String eId) {
        if (this.takenBy != null) {
            return takenBy != null && this.takenBy.hashCode() == takenBy.hashCode() && isAcquired() && StringUtils.equals(sourceSignature, this.sourceSignature) && StringUtils.equals(eId, this.eId);
        } else {
            return false;
        }
    }

    public void resetLock() {
        lock = new Semaphore(1);
        ThreadLocalSSRFMap.getInstance().cleanUp();
        takenBy = null;
        sourceSignature = StringUtils.EMPTY;
        eId = StringUtils.EMPTY;
        url = StringUtils.EMPTY;
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

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

}
