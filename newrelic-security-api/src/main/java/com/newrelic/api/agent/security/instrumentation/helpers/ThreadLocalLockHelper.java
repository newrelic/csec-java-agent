package com.newrelic.api.agent.security.instrumentation.helpers;

import java.util.concurrent.locks.ReentrantLock;

public class ThreadLocalLockHelper {

    private static final ThreadLocal<ReentrantLock> csecOperationLock = ThreadLocal.withInitial(ReentrantLock::new);

    public static boolean isLockHeldByCurrentThread() {
        ReentrantLock lock = csecOperationLock.get();
        return lock.isHeldByCurrentThread();
    }

    public static boolean acquireLock() {
        ReentrantLock lock = csecOperationLock.get();
        synchronized (lock) {
            if(!lock.isHeldByCurrentThread()){
                lock.lock();
                return true;
            }
        }
        return false;
    }

    public static void releaseLock() {
        ReentrantLock lock = csecOperationLock.get();
        synchronized (lock) {
            if(lock.isHeldByCurrentThread()){
                lock.unlock();
            }
        }
    }

}
