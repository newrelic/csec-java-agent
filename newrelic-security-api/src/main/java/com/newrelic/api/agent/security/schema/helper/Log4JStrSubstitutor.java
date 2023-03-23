package com.newrelic.api.agent.security.schema.helper;

public class Log4JStrSubstitutor {

    private String variableName;

    private StringBuilder buf;

    private int startPos;

    private int endPos;

    public Log4JStrSubstitutor(String variableName, StringBuilder buf, int startPos, int endPos) {
        this.variableName = variableName;
        this.buf = buf;
        this.startPos = startPos;
        this.endPos = endPos;
    }

    public String getVariableName() {
        return variableName;
    }

    public void setVariableName(String variableName) {
        this.variableName = variableName;
    }

    public StringBuilder getBuf() {
        return buf;
    }

    public void setBuf(StringBuilder buf) {
        this.buf = buf;
    }

    public int getStartPos() {
        return startPos;
    }

    public void setStartPos(int startPos) {
        this.startPos = startPos;
    }

    public int getEndPos() {
        return endPos;
    }

    public void setEndPos(int endPos) {
        this.endPos = endPos;
    }
}
