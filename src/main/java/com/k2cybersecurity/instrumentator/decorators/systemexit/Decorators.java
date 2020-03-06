package com.k2cybersecurity.instrumentator.decorators.systemexit;
import com.k2cybersecurity.instrumentator.custom.K2CyberSecurityException;
import com.k2cybersecurity.instrumentator.utils.ExecutionIDGenerator;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.implementation.bytecode.assign.Assigner;
import org.apache.commons.lang3.StringUtils;

public class Decorators {
    public static class ConstructorExit {

//	private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

        @Advice.OnMethodExit()
        public static void exit(@Advice.Origin String signature, @Advice.Origin("#t") String className, @Advice.Origin("#m") String methodName, @Advice.AllArguments Object[] args, @Advice.This Object thisObject) throws Throwable{
            try {
                String threadName = Thread.currentThread().getName();
                if (StringUtils.startsWith(threadName, "K2-")) {
                    return;
                }
                String executionId = ExecutionIDGenerator.getExecutionId();
                Callbacks.doOnExit(signature, className, methodName, thisObject, args, null, executionId);
            } catch (Throwable e) {
                if(e instanceof K2CyberSecurityException){
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
        public static Object enter(@Advice.Origin String signature, @Advice.Origin("#t") String className, @Advice.Origin("#m") String methodName, @Advice.AllArguments Object[] args, @Advice.This Object thisArg) throws Throwable{
            try {
                String threadName = Thread.currentThread().getName();
                if (StringUtils.startsWith(threadName, "K2-")) {
                    return null;
                }
                String executionId = ExecutionIDGenerator.getExecutionId();
                Callbacks.doOnEnter(signature, className, methodName, thisArg, args, executionId);
            } catch (Throwable e) {
                if(e instanceof K2CyberSecurityException){
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
        public static void exit(@Advice.Origin String signature, @Advice.Origin("#t") String className, @Advice.Origin("#m") String methodName, @Advice.Return(readOnly = false, typing = Assigner.Typing.DYNAMIC) Object value, @Advice.Thrown Throwable error, @Advice.This Object thisArg, @Advice.AllArguments Object[] args)
                throws Throwable {
            try {
                String threadName = Thread.currentThread().getName();
                if (StringUtils.startsWith(threadName, "K2-")) {
                    return;
                }
                String executionId = ExecutionIDGenerator.getExecutionId();
                if (error == null) {
                    Callbacks.doOnExit(signature, className, methodName, thisArg, args, value, executionId);
                } else {
                    Callbacks.doOnError(signature, className, methodName, thisArg, args, error, executionId);
                }
            } catch (Throwable e) {
                if(e instanceof K2CyberSecurityException){
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
        public static void exit(@Advice.Origin String signature, @Advice.Origin("#t") String className, @Advice.Origin("#m") String methodName, @Advice.Thrown Throwable error, @Advice.This Object thisArg, @Advice.AllArguments Object[] args)
                throws Throwable {
            try {
                String threadName = Thread.currentThread().getName();
                if (StringUtils.startsWith(threadName, "K2-")) {
                    return;
                }
                String executionId = ExecutionIDGenerator.getExecutionId();
                if (error == null) {
                    Callbacks.doOnExit(signature, className, methodName, thisArg, args, null, executionId);
                } else {
                    Callbacks.doOnError(signature, className, methodName, thisArg, args, error, executionId);
                }
            } catch (Throwable e) {
                if(e instanceof K2CyberSecurityException){
                    e.printStackTrace();

                    //throw e;
                }
//        	logger.log(LogLevel.ERROR, "Error: ", e, MethodVoidExit.class.getName());
            }
        }
    }

    public static class StaticMethodEntry {

//	private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

        @Advice.OnMethodEnter
        public static Object enter(@Advice.Origin String signature, @Advice.Origin("#t") String className, @Advice.Origin("#m") String methodName, @Advice.AllArguments Object[] args) throws Throwable{
            try {
                String threadName = Thread.currentThread().getName();
                if (StringUtils.startsWith(threadName, "K2-")) {
                    return null;
                }
                String executionId = ExecutionIDGenerator.getExecutionId();
                Callbacks.doOnEnter(signature, className, methodName, null, args, executionId);
            } catch (Throwable e) {
                if(e instanceof K2CyberSecurityException){
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
        public static void exit(@Advice.Origin String signature, @Advice.Origin("#t") String className, @Advice.Origin("#m") String methodName, @Advice.Return(readOnly = false, typing = Assigner.Typing.DYNAMIC) Object value, @Advice.Thrown Throwable error, @Advice.AllArguments Object[] args)
                throws Throwable {
            try {
                String threadName = Thread.currentThread().getName();
                if (StringUtils.startsWith(threadName, "K2-")) {
                    return;
                }
                String executionId = ExecutionIDGenerator.getExecutionId();
                if (error == null) {
                    Callbacks.doOnExit(signature, className, methodName, null, args, value, executionId);
                } else {
                    Callbacks.doOnError(signature, className, methodName, null, args, error, executionId);
                }
            } catch (Throwable e) {
                if(e instanceof K2CyberSecurityException){
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
        public static void exit(@Advice.Origin String signature, @Advice.Origin("#t") String className, @Advice.Origin("#m") String methodName, @Advice.Thrown Throwable error, @Advice.AllArguments Object[] args)
                throws Throwable {
            String executionId = ExecutionIDGenerator.getExecutionId();
            try {
                String threadName = Thread.currentThread().getName();
                if (StringUtils.startsWith(threadName, "K2-")) {
                    return;
                }
                if (error == null) {
                    Callbacks.doOnExit(signature, className, methodName, null, args, null, executionId);
                } else {
                    Callbacks.doOnError(signature, className, methodName, null, args, error, executionId);
                }
            } catch (Throwable e) {
                if(e instanceof K2CyberSecurityException){
                    e.printStackTrace();

                    //throw e;
                }
//        	logger.log(LogLevel.ERROR, "Error: ", e, StaticMethodVoidExit.class.getName());
            }
        }

    }
}