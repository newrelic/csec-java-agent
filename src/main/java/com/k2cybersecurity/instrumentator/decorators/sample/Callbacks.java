package com.k2cybersecurity.instrumentator.decorators.sample;

import java.util.Arrays;

public class Callbacks {

	public static void doOnEnter(String sourceString, Object obj, Object[] args, String exectionId){
		System.out.println("OnEnter :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj + " - eid : " + exectionId);
	}

	public static void doOnExit(String sourceString, Object obj, Object[] args, Object returnVal, String exectionId){
		System.out.println("OnExit :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj + " - return : " + returnVal + " - eid : " + exectionId);
	}

	public static void doOnError(String sourceString, Object obj, Object[] args, Throwable error, String exectionId){
		System.out.println("OnExit :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj + " - error : " + error + " - eid : " + exectionId);
	}
}
