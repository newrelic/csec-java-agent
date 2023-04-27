package com.newrelic.agent.security.intcodeagent.filelogging;

public enum LogLevel {

    FINEST(7),
    FINER(6),
    FINE(5),
    INFO(4),
    WARNING(3),
    SEVERE(2),
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
