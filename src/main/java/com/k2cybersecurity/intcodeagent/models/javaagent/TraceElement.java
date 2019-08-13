package com.k2cybersecurity.intcodeagent.models.javaagent;

import java.io.Serializable;

import com.k2cybersecurity.intcodeagent.websocket.JsonConverter;

public class TraceElement implements Serializable{
	/**
	 * 
	 */
	private static final long serialVersionUID = -495570272645645109L;
	
	private String className;
	private String methodName;
	private int lineNumber;
	
	public TraceElement() {}
	
	public TraceElement(TraceElement element){
		this.className = element.className;
		this.methodName = element.methodName;
		this.lineNumber = element.lineNumber;
	}

	/**
	 * @return the className
	 */
	public String getClassName() {
		return className;
	}

	/**
	 * @param className the className to set
	 */
	public void setClassName(String className) {
		this.className = className;
	}

	/**
	 * @return the methodName
	 */
	public String getMethodName() {
		return methodName;
	}

	/**
	 * @param methodName the methodName to set
	 */
	public void setMethodName(String methodName) {
		this.methodName = methodName;
	}

	/**
	 * @return the lineNumber
	 */
	public int getLineNumber() {
		return lineNumber;
	}

	/**
	 * @param lineNumber the lineNumber to set
	 */
	public void setLineNumber(int lineNumber) {
		this.lineNumber = lineNumber;
	}
	
	@Override
	public String toString() {
		return JsonConverter.toJSON(this);
	}
	
}
