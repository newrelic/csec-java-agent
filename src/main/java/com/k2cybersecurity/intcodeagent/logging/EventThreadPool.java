package com.k2cybersecurity.intcodeagent.logging;

import java.io.ObjectOutputStream;
import java.net.Socket;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.Future;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.RejectedExecutionHandler;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

public class EventThreadPool {

	/** Thread pool executor. */
	private ThreadPoolExecutor executor;

	private static EventThreadPool instance;
	
	private StringBuffer eventBuffer;
	
	private Map<String,String> mySqlPreparedStatementsMap;
	private LinkedBlockingQueue<Object> eventQueue = new LinkedBlockingQueue<>(5000);
	private Socket socket;
	private ObjectOutputStream oos;
	private ScheduledExecutorService eventPoolExecutor;
	private static Object mutex = new Object();
	
	private EventThreadPool() {
		LinkedBlockingQueue<Runnable> processQueue;
		// load the settings
		int queueSize = 700;
		int maxPoolSize = 10;
		int corePoolSize = 1;
		long keepAliveTime = 10;
		
		TimeUnit timeUnit = TimeUnit.SECONDS;

		boolean allowCoreThreadTimeOut = false;

		if (queueSize == 0) {
			processQueue = new LinkedBlockingQueue<>();
		} else {
			processQueue = new LinkedBlockingQueue<>(queueSize);
		}

		executor = new ThreadPoolExecutor(corePoolSize, maxPoolSize, keepAliveTime, timeUnit, processQueue,
				new EventAbortPolicy()) {

			@Override
			protected void afterExecute(Runnable r, Throwable t) {
				if (r instanceof Future<?>) {
					try {
						Future<?> future = (Future<?>) r;
						if (future.isDone()) {
							future.get();
						}
					} catch (Exception e) {
					}
				}
				super.afterExecute(r, t);
			}

		};
		this.eventBuffer = new StringBuffer();
		this.mySqlPreparedStatementsMap = new HashMap<String,String>();
		executor.allowCoreThreadTimeOut(allowCoreThreadTimeOut);
		executor.setThreadFactory(new ThreadFactory() {
			private final AtomicInteger threadNumber = new AtomicInteger(1);

			@Override
			public Thread newThread(Runnable r) {
				return new Thread(Thread.currentThread().getThreadGroup(), r,
						"K2-Java-Agent-" + threadNumber.getAndIncrement());
			}
		});
	}

	protected static EventThreadPool getInstance() {

		if (instance == null) {
			synchronized (mutex) {
				if (instance == null) {
					instance = new EventThreadPool();
				}
				return instance;
			}
		}
		return instance;
	}

	/**
	 * A handler for rejected tasks that throws a
	 * {@code RejectedExecutionException}.
	 */
	public static class EventAbortPolicy implements RejectedExecutionHandler {
		/**
		 * Creates an {@code ValidationAbortPolicy}.
		 */
		public EventAbortPolicy() {
		}

		/**
		 * Always throws RejectedExecutionException.
		 *
		 * @param r
		 *            the runnable task requested to be executed
		 * @param e
		 *            the executor attempting to execute this task
		 * @throws RejectedExecutionException
		 *             always
		 */
		public void rejectedExecution(Runnable r, ThreadPoolExecutor e) {
			System.out.println("Event Task " + r.toString() + " rejected from {} " + e.toString());
		}
	}


	public void processReceivedEvent(Object source, Object[] arg, Integer executionId, StackTraceElement[] stackTrace, long tId, String sourceString) {
		try {
			this.executor.execute(new ProcessorThread(source, arg, executionId, stackTrace, tId, sourceString));
		} catch (Exception e) {

		}
	}
	
	protected boolean isQueueEmpty() {
		return this.executor.getQueue().isEmpty();
	}

	/**
	 * @return the eventBuffer
	 */
	public StringBuffer getEventBuffer() {
		return eventBuffer;
	}
	
	/**
	 * @return the eventBuffer
	 */
	public StringBuffer renewEventBuffer() {
		return this.eventBuffer = new StringBuffer();
	}

	public String getMySqlPreparedStatementsMap(String id) {
		if(this.mySqlPreparedStatementsMap.containsKey(id)) {
			return this.mySqlPreparedStatementsMap.get(id);
		}
		return null;
	}
	
	public void setMySqlPreparedStatementsMap(String id, String sql) {
		if (sql==null && this.mySqlPreparedStatementsMap.containsKey(id)) {
			this.mySqlPreparedStatementsMap.remove(id);
		} else {
			this.mySqlPreparedStatementsMap.put(id, sql);
		}
	}
	
	public LinkedBlockingQueue<Object> getEventQueue() {
		return eventQueue;
	}

	public Socket getSocket() {
		return socket;
	}

	public void setSocket(Socket socket) {
		this.socket = socket;
	}

	public ObjectOutputStream getObjectStream() {
		return oos;
	}

	public void setObjectStream(ObjectOutputStream oos) {
		this.oos = oos;
	}

	public ScheduledExecutorService getEventPoolExecutor() {
		return eventPoolExecutor;
	}

	public void setEventPoolExecutor(ScheduledExecutorService eventPoolExecutor) {
		this.eventPoolExecutor = eventPoolExecutor;
	}

}
