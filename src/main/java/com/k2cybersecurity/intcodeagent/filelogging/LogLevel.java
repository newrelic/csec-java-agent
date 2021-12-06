package com.k2cybersecurity.intcodeagent.filelogging;

public enum LogLevel {

    ALL(7),
    DEBUG(6),
    INFO(5),
    WARN(4),
    ERROR(3),
    FATAL(2),
    OFF(1);

    private int level;

    private LogLevel(int level) {
        this.level = level;
    }

    public int getLevel() {
        return this.level;
    }

    public static String getLevelName(int level) {
        for(LogLevel lvl : LogLevel.values()){
            if (lvl.getLevel() == level){
                return lvl.name();
            }
        }
        return "Unknown";
    }
}
