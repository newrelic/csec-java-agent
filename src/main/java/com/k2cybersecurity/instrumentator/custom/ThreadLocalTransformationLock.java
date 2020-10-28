package com.k2cybersecurity.instrumentator.custom;

import java.util.concurrent.Semaphore;

public class ThreadLocalTransformationLock {

	private Semaphore lock;

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
