package com.k2cybersecurity.intcodeagent.logging;

import java.io.BufferedReader;
import java.io.FileReader;
import java.net.SocketException;
import java.util.Collections;
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
				try (BufferedReader reader = new BufferedReader(new FileReader("/etc/k2-adp/hostip.properties"))) {
					String hostip = reader.readLine();
					
					try {
						// since tcp connection keep alive check is more than 2 hours
						// we send our custom object to check if connectino is still alive or not
						// this will be ignored by ic agent on the other side.
					System.out.println("writing ack object");
					LoggingInterceptor.oos.writeObject(Collections.singletonList("ACK"));
					LoggingInterceptor.oos.flush();
					} catch (SocketException ex) {
						System.out.println("Error in writing : " + ex.getMessage());
						System.out.println("Host ip equals : " + LoggingInterceptor.hostip.equals(hostip));
						System.out.println("LoggingInterceptor.socket : " + LoggingInterceptor.socket);
						// if ack fails, socket needs to be properly closed as it is not done implicitly
						LoggingInterceptor.closeSocket();
					}
					catch (Exception ex) {
						System.out.println(ex.getMessage());
					}
					if (hostip == null || hostip.equals("")) {
						System.out.println("Host ip not found");
					} else if (!LoggingInterceptor.hostip.equals(hostip) || (LoggingInterceptor.socket == null
							|| !LoggingInterceptor.socket.isConnected() || LoggingInterceptor.socket.isClosed())) {
						LoggingInterceptor.connectSocket();
						LoggingInterceptor.createApplicationInfoBean();
						LoggingInterceptor.getJarPath();
						System.out.println("K2-JavaAgent re-installed successfully.");
					} else {
						System.out.println("got into final else should be only in case of ack written successfully");
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
						"ipScheduledThread-" + threadNumber.getAndIncrement());
			}
		});
		ipScheduledService.scheduleAtFixedRate(runnable, 2, 2, TimeUnit.MINUTES);
	}

	public static IPScheduledThread getInstance() {
		if (instance == null)
			instance = new IPScheduledThread();
		return instance;
	}
}
