package com.k2cybersecurity.instrumentator.decorators.jettyhandle;

import com.k2cybersecurity.instrumentator.custom.K2CyberSecurityException;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalTransformationLock;
import com.k2cybersecurity.instrumentator.utils.AgentUtils;
import com.k2cybersecurity.instrumentator.utils.ExecutionIDGenerator;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.implementation.bytecode.assign.Assigner;
import org.apache.commons.lang3.StringUtils;

public class Decorators {
    public static class ConstructorExit {

//	private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

        @Advice.OnMethodExit()
        public static void exit(@Advice.Origin String signature, @Advice.Origin Class<?> classRef, @Advice.Origin("#m") String methodName, @Advice.AllArguments Object[] args, @Advice.This Object thisObject, @Advice.Local("k2execId") String eId) throws Throwable {
            try {
                if (!AgentUtils.getInstance().isAgentActive() || ThreadLocalTransformationLock.getInstance().isAcquired()) {
                    return;
                }
                String threadName = Thread.currentThread().getName();
                if (StringUtils.startsWith(threadName, "K2-")) {
                    return;
                }
                Callbacks.doOnExit(signature, classRef, methodName, thisObject, args, null, eId);
            } catch (Throwable e) {
                if (e instanceof K2CyberSecurityException) {
                    e.printStackTrace();
                    //throw e;
                }
//        	logger.log(LogLevel.ERROR, "Error: ", e, ConstructorExit.class.getName());
            }
        }
    }

    public static class MethodEntry {

//	private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

        @Advice.OnMethodEnter(skipOn = K2CyberSecurityException.class)
        public static Object enter(@Advice.Origin String signature, @Advice.Origin Class<?> classRef, @Advice.Origin("#m") String methodName, @Advice.AllArguments Object[] args, @Advice.This Object thisArg, @Advice.Local("k2execId") String eId) throws Throwable {
            try {
                if (!AgentUtils.getInstance().isAgentActive() || ThreadLocalTransformationLock.getInstance().isAcquired()) {
                    return null;
                }
                String threadName = Thread.currentThread().getName();
                if (StringUtils.startsWith(threadName, "K2-")) {
                    return null;
                }
                String executionId = ExecutionIDGenerator.getExecutionId();
                eId = new String(executionId);
                Callbacks.doOnEnter(signature, classRef, methodName, thisArg, args, eId);
            } catch (Throwable e) {
                if (e instanceof K2CyberSecurityException) {
                    e.printStackTrace();
                    return e;
                }
//        	logger.log(LogLevel.ERROR, "Error: ", e, MethodEntry.class.getName());
            }
            return null;
        }
    }

    public static class MethodExit {

//	private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

        @Advice.OnMethodExit(onThrowable = Exception.class)
        public static void exit(@Advice.Origin String signature, @Advice.Origin Class<?> classRef, @Advice.Origin("#m") String methodName, @Advice.Return(readOnly = false, typing = Assigner.Typing.DYNAMIC) Object value, @Advice.Thrown Throwable error, @Advice.This Object thisArg, @Advice.AllArguments Object[] args, @Advice.Local("k2execId") String eId)
                throws Throwable {
            try {
                if (!AgentUtils.getInstance().isAgentActive() || ThreadLocalTransformationLock.getInstance().isAcquired()) {
                    return;
                }
                String threadName = Thread.currentThread().getName();
                if (StringUtils.startsWith(threadName, "K2-")) {
                    return;
                }
//                String executionId = ExecutionIDGenerator.getExecutionId();
                if (error == null) {
                    Callbacks.doOnExit(signature, classRef, methodName, thisArg, args, value, eId);
                } else {
                    Callbacks.doOnError(signature, classRef, methodName, thisArg, args, error, eId);
                }
            } catch (Throwable e) {
                if (e instanceof K2CyberSecurityException) {
                    e.printStackTrace();

                    //throw e;
                }
//        	logger.log(LogLevel.ERROR, "Error: ", e, MethodExit.class.getName());
            }
        }

    }

    public static class MethodVoidExit {

//	private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

        @Advice.OnMethodExit(onThrowable = Exception.class)
        public static void exit(@Advice.Origin String signature, @Advice.Origin Class<?> classRef, @Advice.Origin("#m") String methodName, @Advice.Thrown Throwable error, @Advice.This Object thisArg, @Advice.AllArguments Object[] args, @Advice.Local("k2execId") String eId)
                throws Throwable {
            try {
                if (!AgentUtils.getInstance().isAgentActive() || ThreadLocalTransformationLock.getInstance().isAcquired()) {
                    return;
                }
                String threadName = Thread.currentThread().getName();
                if (StringUtils.startsWith(threadName, "K2-")) {
                    return;
                }
//                String executionId = ExecutionIDGenerator.getExecutionId();
                if (error == null) {
                    Callbacks.doOnExit(signature, classRef, methodName, thisArg, args, null, eId);
                } else {
                    Callbacks.doOnError(signature, classRef, methodName, thisArg, args, error, eId);
                }
            } catch (Throwable e) {
                if (e instanceof K2CyberSecurityException) {
                    e.printStackTrace();

                    //throw e;
                }
//        	logger.log(LogLevel.ERROR, "Error: ", e, MethodVoidExit.class.getName());
            }
        }
    }

    public static class StaticMethodEntry {

//	private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

        @Advice.OnMethodEnter(skipOn = K2CyberSecurityException.class)
        public static Object enter(@Advice.Origin String signature, @Advice.Origin Class<?> classRef, @Advice.Origin("#m") String methodName, @Advice.AllArguments Object[] args, @Advice.Local("k2execId") String eId) throws Throwable {
            try {
                if (!AgentUtils.getInstance().isAgentActive() || ThreadLocalTransformationLock.getInstance().isAcquired()) {
                    return null;
                }
                String threadName = Thread.currentThread().getName();
                if (StringUtils.startsWith(threadName, "K2-")) {
                    return null;
                }
                String executionId = ExecutionIDGenerator.getExecutionId();
                eId = new String(executionId);
                Callbacks.doOnEnter(signature, classRef, methodName, null, args, eId);
            } catch (Throwable e) {
                if (e instanceof K2CyberSecurityException) {
                    e.printStackTrace();
                    return e;
                }
//        	logger.log(LogLevel.ERROR, "Error: ", e, StaticMethodEntry.class.getName());
            }
            return null;
        }

    }


    public static class ConstructorEntry {

//	private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

        @Advice.OnMethodEnter
        public static Object enter(@Advice.Origin String signature, @Advice.Origin Class<?> classRef, @Advice.Origin("#m") String methodName, @Advice.AllArguments Object[] args, @Advice.Local("k2execId") String eId) throws Throwable {
            try {
                if (!AgentUtils.getInstance().isAgentActive() || ThreadLocalTransformationLock.getInstance().isAcquired()) {
                    return null;
                }
                String threadName = Thread.currentThread().getName();
                if (StringUtils.startsWith(threadName, "K2-")) {
                    return null;
                }
                String executionId = ExecutionIDGenerator.getExecutionId();
                eId = new String(executionId);
                Callbacks.doOnEnter(signature, classRef, methodName, null, args, eId);
            } catch (Throwable e) {
                if (e instanceof K2CyberSecurityException) {
                    e.printStackTrace();
                    return e;
                }
//        	logger.log(LogLevel.ERROR, "Error: ", e, StaticMethodEntry.class.getName());
            }
            return null;
        }

    }


    public static class StaticMethodExit {

//	private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

        @Advice.OnMethodExit(onThrowable = Exception.class)
        public static void exit(@Advice.Origin String signature, @Advice.Origin Class<?> classRef, @Advice.Origin("#m") String methodName, @Advice.Return(readOnly = false, typing = Assigner.Typing.DYNAMIC) Object value, @Advice.Thrown Throwable error, @Advice.AllArguments Object[] args, @Advice.Local("k2execId") String eId)
                throws Throwable {
            try {
                if (!AgentUtils.getInstance().isAgentActive() || ThreadLocalTransformationLock.getInstance().isAcquired()) {
                    return;
                }
                String threadName = Thread.currentThread().getName();
                if (StringUtils.startsWith(threadName, "K2-")) {
                    return;
                }
//                String executionId = ExecutionIDGenerator.getExecutionId();
                if (error == null) {
                    Callbacks.doOnExit(signature, classRef, methodName, null, args, value, eId);
                } else {
                    Callbacks.doOnError(signature, classRef, methodName, null, args, error, eId);
                }
            } catch (Throwable e) {
                if (e instanceof K2CyberSecurityException) {
                    e.printStackTrace();

                    //throw e;
                }
//        	logger.log(LogLevel.ERROR, "Error: ", e, StaticMethodExit.class.getName());
            }
        }

    }


    public static class StaticMethodVoidExit {

//	private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

        @Advice.OnMethodExit(onThrowable = Exception.class)
        public static void exit(@Advice.Origin String signature, @Advice.Origin Class<?> classRef, @Advice.Origin("#m") String methodName, @Advice.Thrown Throwable error, @Advice.AllArguments Object[] args, @Advice.Local("k2execId") String eId)
                throws Throwable {
//            String executionId = ExecutionIDGenerator.getExecutionId();
            try {
                if (!AgentUtils.getInstance().isAgentActive() || ThreadLocalTransformationLock.getInstance().isAcquired()) {
                    return;
                }
                String threadName = Thread.currentThread().getName();
                if (StringUtils.startsWith(threadName, "K2-")) {
                    return;
                }
                if (error == null) {
                    Callbacks.doOnExit(signature, classRef, methodName, null, args, null, eId);
                } else {
                    Callbacks.doOnError(signature, classRef, methodName, null, args, error, eId);
                }
            } catch (Throwable e) {
                if (e instanceof K2CyberSecurityException) {
                    e.printStackTrace();

                    //throw e;
                }
//        	logger.log(LogLevel.ERROR, "Error: ", e, StaticMethodVoidExit.class.getName());
            }
        }

    }
}