package com.k2cybersecurity.intcodeagent.logging;

public class K2Native {

	static {
		System.load("/etc/k2-adp/k2JavaNative.so");
	}

	protected static native int k2init();

	protected static native int k2test(String s);

}
