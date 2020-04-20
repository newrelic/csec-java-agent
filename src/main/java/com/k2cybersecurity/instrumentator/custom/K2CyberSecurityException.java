package com.k2cybersecurity.instrumentator.custom;

public class K2CyberSecurityException extends Throwable {

	public K2CyberSecurityException() {
		super("Security exception raised.");
	}

	public K2CyberSecurityException(String message) {
		super(message);
	}

	public K2CyberSecurityException(String message, Throwable cause) {
		super(message, cause);
	}

	public K2CyberSecurityException(Throwable cause) {
		super(cause);
	}
}
