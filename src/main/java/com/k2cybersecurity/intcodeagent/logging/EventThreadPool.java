package com.k2cybersecurity.intcodeagent.logging;

import java.io.IOException;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executor;
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
	private static short MAX_BLOCKING_QUEUE_SIZE = 3000;
	private static Object mutex = new Object();

	private StringBuffer eventBuffer;
	private LinkedBlockingQueue<Object> eventQueue = new LinkedBlockingQueue<>(MAX_BLOCKING_QUEUE_SIZE);
	private Socket socket;
	private ObjectOutputStream oos;
	private ScheduledExecutorService eventPoolExecutor;
	private Runnable queuePooler;
	private boolean triedReconnect = false;
	
	final int queueSize = 300;
	final int maxPoolSize = 3;
	final int corePoolSize = 1;
	final long keepAliveTime = 10;
	
	private EventThreadPool() {
		LinkedBlockingQueue<Runnable> processQueue;
		// load the settings

		TimeUnit timeUnit = TimeUnit.SECONDS;

		boolean allowCoreThreadTimeOut = false;
		processQueue = new LinkedBlockingQueue<>(queueSize);
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
		executor.allowCoreThreadTimeOut(allowCoreThreadTimeOut);
		executor.setThreadFactory(new ThreadFactory() {
			private final AtomicInteger threadNumber = new AtomicInteger(1);

			@Override
			public Thread newThread(Runnable r) {
				return new Thread(Thread.currentThread().getThreadGroup(), r,
						IAgentConstants.K2_JAVA_AGENT + threadNumber.getAndIncrement());
			}
		});
		this.queuePooler = new Runnable() {
			@Override
			public void run() {
				EventThreadPool currentExecutor =  EventThreadPool.getInstance();
				LinkedBlockingQueue<Object> eventQueue = currentExecutor.getEventQueue();
				if (!eventQueue.isEmpty()) {
					try {
						
						ObjectOutputStream oos = currentExecutor.getObjectStream();
						List<Object> eventList = new ArrayList<>();
						eventQueue.drainTo(eventList, eventQueue.size());
						oos.writeUnshared(eventList);
//						System.out.println("EventThreadPool Pending Events: " + EventThreadPool.getInstance().getExecutor().getQueue().size());
//						System.out.println("eventList size before send: " + eventList.size()
//								+ ", EventQueue size after drain: " + eventQueue.size());
						oos.reset();
						if(currentExecutor.triedReconnect()) {
							currentExecutor.setTriedReconnect(false);
						}
					} catch (IOException e) {
						System.err.println("Error in writing: " + e.getMessage());
						if(!currentExecutor.triedReconnect()) {
							LoggingInterceptor.closeSocket();
							LoggingInterceptor.connectSocket();
							LoggingInterceptor.createApplicationInfoBean();
							currentExecutor.setTriedReconnect(true);
						}
//						e.printStackTrace();
					} catch (Exception e) {
						e.printStackTrace();
					}
				}
			}
		};
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
		 * @param r the runnable task requested to be executed
		 * @param e the executor attempting to execute this task
		 * @throws RejectedExecutionException always
		 */
		public void rejectedExecution(Runnable r, ThreadPoolExecutor e) {
			System.out.println("Event Task " + r.toString() + " rejected from {} " + e.toString());
		}
	}

	public void processReceivedEvent(Object source, Object[] arg, Integer executionId, StackTraceElement[] stackTrace,
			long tId, String sourceString) {
		try {
			this.executor.execute(new ProcessorThread(source, arg, executionId, stackTrace, tId, sourceString));
		} catch (RejectedExecutionException rejected) {
			System.err.println("Rejected to process Event At: " + this.executor.getQueue().size());
			rejected.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
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

	// TODO: remove this getter
	protected ThreadPoolExecutor getExecutor() {
		return executor;
	}

	protected Runnable getQueuePooler() {
		return queuePooler;
	}

	public boolean triedReconnect() {
		return triedReconnect;
	}

	public void setTriedReconnect(boolean triedReconnect) {
		this.triedReconnect = triedReconnect;
	}
	
	
}
