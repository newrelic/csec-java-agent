package org.brutusin.instrumentation.logging;


import java.io.BufferedReader;
import java.io.FileReader;
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
					if (hostip == null || hostip.equals("")) {
						System.out.println("Host ip not found");
					} else {
						if (!LoggingInterceptor.hostip.equals(hostip)) {
							LoggingInterceptor.connectSocket();
							LoggingInterceptor.createApplicationInfoBean();
							System.out.println("K2-JavaAgent re-installed successfully.");
						}
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
		ipScheduledService.scheduleAtFixedRate(runnable, 5, 5, TimeUnit.MINUTES);
	}

	public static IPScheduledThread getInstance() {
		if (instance == null)
			instance = new IPScheduledThread();
		return instance;
	}
}
