package com.k2cybersecurity.instrumentator.custom;

import org.apache.commons.lang3.StringUtils;

import java.util.concurrent.Semaphore;

public class ThreadLocalJNDILock {

    private Semaphore lock;

    private Object takenBy;

    private String sourceSignature = StringUtils.EMPTY;

    private String eId = StringUtils.EMPTY;

    private StringBuilder buf = null;

    private String mappingValue = StringUtils.EMPTY;

    private int startPos = -1;

    private int endPos = -1;

    private static ThreadLocal<ThreadLocalJNDILock> instance = new ThreadLocal<ThreadLocalJNDILock>() {
        @Override
        protected ThreadLocalJNDILock initialValue() {
            return new ThreadLocalJNDILock();
        }
    };

    private ThreadLocalJNDILock() {
        lock = new Semaphore(1);
    }

    public static ThreadLocalJNDILock getInstance() {
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
            resetLock();
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

    private void resetLock() {
        lock.release();
        takenBy = null;
        sourceSignature = StringUtils.EMPTY;
        eId = StringUtils.EMPTY;
        buf = null;
        mappingValue = StringUtils.EMPTY;
        startPos = -1;
        endPos = -1;
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

    public StringBuilder getBuf() {
        return buf;
    }

    public void setBuf(StringBuilder buf) {
        this.buf = buf;
    }

    public String getMappingValue() {
        return mappingValue;
    }

    public void setMappingValue(String mappingValue) {
        this.mappingValue = mappingValue;
    }

    public int getStartPos() {
        return startPos;
    }

    public void setStartPos(int startPos) {
        this.startPos = startPos;
    }

    public int getEndPos() {
        return endPos;
    }

    public void setEndPos(int endPos) {
        this.endPos = endPos;
    }


    
}
