package com.k2cybersecurity.intcodeagent.logging;

import java.io.BufferedReader;
import java.io.FileReader;
import java.net.Socket;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

public class IPScheduledThread {

	private static IPScheduledThread instance;

	private static ScheduledExecutorService ipScheduledService;

	private IPScheduledThread() {
		Runnable runnable = new Runnable() {
			public void run() {
				Socket socket = EventThreadPool.getInstance().getSocket();
				try (BufferedReader reader = new BufferedReader(new FileReader(IAgentConstants.HOST_IP_PROPERTIES_FILE))) {
					String hostip = reader.readLine();
					try {
					System.out.println("Host ip equals : " + LoggingInterceptor.hostip.equals(hostip));
					System.out.println("LoggingInterceptor.socket : " + socket);
					System.out.println("LoggingInterceptor.socket.isConnected() : " + socket.isConnected());
					System.out.println("LoggingInterceptor.socket.isClosed() : " + socket.isClosed());
					} catch (Exception ex) {
						ex.printStackTrace();
					}
					if (hostip == null || hostip.equals(IAgentConstants.EMPTY_STRING)) {
						System.out.println("Host ip not found");
					} else if (!LoggingInterceptor.hostip.equals(hostip) || (socket == null
							|| !socket.isConnected() || socket.isClosed())) {
						LoggingInterceptor.connectSocket();
						LoggingInterceptor.createApplicationInfoBean();
						LoggingInterceptor.getJarPath();
						System.out.println("K2-JavaAgent re-installed successfully.");
					}
				} catch (Exception e) {
					System.err.println("Error in IPScheduledThread : " + e.getMessage());
					e.printStackTrace();
				}
			}
		};
		ipScheduledService = Executors.newSingleThreadScheduledExecutor(new ThreadFactory() {
			private final AtomicInteger threadNumber = new AtomicInteger(1);
			
			@Override
			public Thread newThread(Runnable r) {
				return new Thread(Thread.currentThread().getThreadGroup(), r,
						IAgentConstants.IPSCHEDULEDTHREAD_ + threadNumber.getAndIncrement());
			}
		});
		ipScheduledService.scheduleAtFixedRate(runnable, 5, 5, TimeUnit.MINUTES);
	}

	public static IPScheduledThread getInstance() {
		if (instance == null)
			instance = new IPScheduledThread();
		return instance;
	}
}
