package com.k2cybersecurity.instrumentator.utils;

import java.io.IOException;
import java.io.InputStream;

import net.bytebuddy.dynamic.ClassFileLocator.ForClassLoader;
import net.bytebuddy.utility.StreamDrainer;

public class K2ClassLocater extends ForClassLoader {

	private final ClassLoader myclassLoader;

	protected K2ClassLocater(ClassLoader classLoader) {
		super(classLoader);
		this.myclassLoader = classLoader;
	}

	@Override
	public Resolution locate(String name) throws IOException {
		InputStream inputStream;
		if (this.myclassLoader == null) {
			inputStream = ClassLoader.getSystemResourceAsStream(name.replace('.', '/') + CLASS_FILE_EXTENSION);
		} else {
			inputStream = this.myclassLoader.getResourceAsStream(name.replace('.', '/') + CLASS_FILE_EXTENSION);
		}
		if (inputStream != null) {
			try {
				return new Resolution.Explicit(StreamDrainer.DEFAULT.drain(inputStream));
			} finally {
				inputStream.close();
			}
		} else {
			return new Resolution.Illegal(name);
		}

	}
}
