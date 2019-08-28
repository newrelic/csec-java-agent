package com.k2cybersecurity.intcodeagent.filelogging;

public enum LogLevel {

	ALL(7),
	DEBUG(6),
	INFO(5),
	WARNING(4),
	ERROR(3),
	SEVERE(2),
	OFF(1);
	
	private int level ;
	private LogLevel(int level) {
		this.level = level;
	}
	
	public int getLevel() {
		return this.level;
	}
}
