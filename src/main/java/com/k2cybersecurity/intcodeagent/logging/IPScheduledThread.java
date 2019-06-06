package com.k2cybersecurity.intcodeagent.logging;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.ObjectOutputStream;
import java.net.Socket;
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

					Socket socket =  EventThreadPool.getInstance().getSocket();
					ObjectOutputStream oos = EventThreadPool.getInstance().getObjectStream();
					try {
						// since tcp connection keep alive check is more than 2 hours
						// we send our custom object to check if connectino is still alive or not
						// this will be ignored by ic agent on the other side.
					    oos.writeUnshared(Collections.singletonList("ACK"));
					} catch (SocketException ex) {
						// if ack fails, socket needs to be properly closed as it is not done implicitly
						System.err.println("Error in writing : " + ex.getMessage());
						LoggingInterceptor.closeSocket();
					} catch (NullPointerException ex) {
						System.err.println("No reference to Socket's OutputStream");
					} catch (Exception e) {
//						e.printStackTrace();
					}
					if (hostip == null || hostip.equals("")) {
						System.err.println("Host ip not found");
					} else if (!LoggingInterceptor.hostip.equals(hostip) || (socket == null)
							|| (!socket.isConnected()) || (socket.isClosed())) {
						LoggingInterceptor.connectSocket();
						LoggingInterceptor.getJarPath();
//						System.out.println("K2-JavaAgent re-installed successfully.");
					} else {
						
					}
				} catch (Exception e) {
					System.err.println("Error in IPScheduledThread : " + e.getMessage());
//					e.printStackTrace();
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
		try {
			if (instance == null)
				instance = new IPScheduledThread();
			return instance;
		} catch (Exception e) {
			e.printStackTrace();
		}
		throw null;
	}
}