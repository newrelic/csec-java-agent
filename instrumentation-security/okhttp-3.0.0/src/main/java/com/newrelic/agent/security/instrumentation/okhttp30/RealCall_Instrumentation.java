/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package com.newrelic.agent.security.instrumentation.okhttp30;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import okhttp3.Request;
import okhttp3.Response;

@Weave(type = MatchType.ExactClass, originalName = "okhttp3.RealCall")
abstract class RealCall_Instrumentation {

    Request originalRequest = Weaver.callOriginal();

    private void releaseLock() {
        try {
            OkhttpHelper.releaseLock();
        } catch (Throwable ignored) {}
    }

    private boolean acquireLockIfPossible() {
        try {
            return OkhttpHelper.acquireLockIfPossible();
        } catch (Throwable ignored) {}
        return false;
    }

    /**
     * Modifying the original request in the constructor might be better, but this is a work-around to a potential
     * problem in the agent accessing constructor parameters in any non-no-arg constructor.
     */
    public Response execute() {
        boolean isLockAcquired = acquireLockIfPossible();
        AbstractOperation operation = null;
        if(isLockAcquired) {
            operation = OkhttpHelper.preprocessSecurityHook(getUrl(originalRequest), this.getClass().getName(),
                    OkhttpHelper.METHOD_EXECUTE);
            Request updatedRequest = OkhttpHelper.addSecurityHeaders(originalRequest.newBuilder(), operation);
            if (updatedRequest != null) {
                originalRequest = updatedRequest;
            }
        }
        Response returnVal = null;
        try {
            returnVal = Weaver.callOriginal();
        } finally {
            if(isLockAcquired){
                releaseLock();
            }
        }
        OkhttpHelper.registerExitOperation(isLockAcquired, operation);
        return returnVal;
    }

    private String getUrl(Request originalRequest) {
        try {
            if (originalRequest != null) {
                return originalRequest.url().toString();
            }
        }catch (Exception e){
            String message = "Instrumentation library: %s , error while generating request URI : %s";
            NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(message, "OKHTTP-3.0.0", e.getMessage()), e, this.getClass().getName());
        }
        return null;
    }

//    @Weave(type = MatchType.ExactClass, originalName = "okhttp3.RealCall$AsyncCall")
//    abstract static class AsyncCall_Instrumentation {
//
//        Request originalRequest = Weaver.callOriginal();
//
//        private void registerExitOperation(boolean isProcessingAllowed, AbstractOperation operation) {
//            try {
//                if (operation == null || !isProcessingAllowed || !NewRelicSecurity.isHookProcessingActive() ||
//                        NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty() || OkhttpHelper.skipExistsEvent()
//                ) {
//                    return;
//                }
//                NewRelicSecurity.getAgent().registerExitEvent(operation);
//            } catch (Throwable ignored){}
//        }
//
//        private AbstractOperation preprocessSecurityHook (String url, String methodName){
//            try {
//                if (!NewRelicSecurity.isHookProcessingActive() ||
//                        NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty() ||
//                        url == null || url.trim().isEmpty()){
//                    return null;
//                }
//                SSRFOperation ssrfOperation = new SSRFOperation(url, this.getClass().getName(), methodName);
//                NewRelicSecurity.getAgent().registerOperation(ssrfOperation);
//                return ssrfOperation;
//            } catch (Throwable e) {
//                if (e instanceof NewRelicSecurityException) {
//                    e.printStackTrace();
//                    throw e;
//                }
//            }
//            return null;
//        }
//
//        private void releaseLock() {
//            try {
//                OkhttpHelper.releaseLock();
//            } catch (Throwable ignored) {}
//        }
//
//        private boolean acquireLockIfPossible() {
//            try {
//                return OkhttpHelper.acquireLockIfPossible();
//            } catch (Throwable ignored) {}
//            return false;
//        }
//
//        private String getUrl(Request originalRequest) {
//            try {
//                if (originalRequest != null) {
//                    return originalRequest.url().toString();
//                }
//            }catch (Exception ignored){}
//            return null;
//        }
//
//        protected void execute() {
//            boolean isLockAcquired = acquireLockIfPossible();
//            System.out.println("real call async execute");
//            AbstractOperation operation = null;
//            if(isLockAcquired) {
//                operation = preprocessSecurityHook(getUrl(originalRequest), OkhttpHelper.METHOD_EXECUTE);
//            }
//            try {
//                Weaver.callOriginal();
//            } finally {
//                if(isLockAcquired){
//                    releaseLock();
//                }
//            }
//            registerExitOperation(isLockAcquired, operation);
//        }
//
//    }

}
