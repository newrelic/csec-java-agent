package com.k2cybersecurity.intcodeagent.logging;

import java.io.File;
import java.io.IOException;
import java.lang.instrument.ClassFileTransformer;
import java.nio.file.FileSystems;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardWatchEventKinds;
import java.nio.file.WatchEvent;
import java.nio.file.WatchKey;
import java.nio.file.WatchService;
import java.util.regex.Pattern;

import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import com.k2cybersecurity.intcodeagent.filelogging.LogLevel;

public class FileWatcher {

	/** Instance of {@link WatchService} */
	private WatchService watchService;

	private Thread fileWatcherThread;

	private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

	private static FileWatcher instance;

	private Pattern k2intcodeActiveFile;

	private ClassFileTransformer classTransformer;

	private Runtime runtime;

	private FileWatcher() {
		k2intcodeActiveFile = Pattern.compile("(k2intcode\\.active)");

		try {
			watchService = FileSystems.getDefault().newWatchService();
			fileWatcherThread = new Thread("JA-watcher") {
				@Override
				public void run() {
					WatchKey key;
					try {
						while ((key = watchService.take()) != null) {
							Path watchDirs = (Path) key.watchable();
							for (WatchEvent<?> event : key.pollEvents()) {
								logger.log(LogLevel.WARNING,
										"Event kind: " + event.kind() + ". File affected: " + event.context(), FileWatcher.class.getName());
								if (event.context() != null) {
									performAction(event, watchDirs);
								} else {
									logger.log(LogLevel.SEVERE,
											"Couldn't find the modified file name, event context found null: " + event, FileWatcher.class.getName());
								}
							}
							key.reset();
						}
					} catch (InterruptedException e) {
						logger.log(LogLevel.SEVERE, "File watcher InterruptedException : ", e, FileWatcher.class.getName());
					}
				}
			};
			fileWatcherThread.start();
		} catch (IOException e) {
			logger.log(LogLevel.SEVERE, "File watcher IOException : ", e, FileWatcher.class.getName());
		}
	}

	protected void performAction(WatchEvent<?> event, Path watchDirs) {
		Path filePath = watchDirs.resolve((Path) event.context()).toAbsolutePath();
		String fileName = filePath.getFileName().toString();
		if (k2intcodeActiveFile.matcher(fileName).matches()) {
			LoggingInterceptor.shutdownLogic(this.runtime, this.classTransformer);
		}
	}

	public void watchDirectory(String fileName) throws IOException {
		File file = new File(fileName);
		if (file.isDirectory()) {
			Paths.get(file.toURI()).register(watchService, StandardWatchEventKinds.ENTRY_DELETE);
		}
	}

	public void watchDirectory(File file) throws IOException {
		if (file.isDirectory()) {
			Paths.get(file.toURI()).register(watchService, StandardWatchEventKinds.ENTRY_DELETE);
		}
	}

	/**
	 * @return the instance
	 */
	public static FileWatcher getInstance() {
		if (instance == null)
			instance = new FileWatcher();
		return instance;
	}

	/**
	 * @return the classTransformer
	 */
	public ClassFileTransformer getClassTransformer() {
		return classTransformer;
	}

	/**
	 * @param classTransformer the classTransformer to set
	 */
	public void setClassTransformer(ClassFileTransformer classTransformer) {
		this.classTransformer = classTransformer;
	}

	/**
	 * @return the runtime
	 */
	public Runtime getRuntime() {
		return runtime;
	}

	/**
	 * @param runtime the runtime to set
	 */
	public void setRuntime(Runtime runtime) {
		this.runtime = runtime;
	}
	
}
